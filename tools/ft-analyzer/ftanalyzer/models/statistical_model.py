"""
Author(s): Tomas Jansky <Tomas.Jansky@progress.com>

Copyright: (C) 2023 Flowmon Networks a.s.
SPDX-License-Identifier: BSD-3-Clause

"""

import atexit
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import ipaddress
import logging
import operator
from os import PathLike
import os
from pathlib import Path
import shutil
import tempfile
import time
from functools import reduce
from typing import Iterable, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from ftanalyzer.common.fast_analyzer_wrapper import (
    create_statistical_model,
    fast_analyzer_available,
    validate_statistical_model,
)
from ftanalyzer.common.pandas_multiprocessing import PandasMultiprocessingHelper
from ftanalyzer.events.events import ExportEvent, FlowStartEvent, FlowEndEvent
from ftanalyzer.models.sm_data_types import (
    SMException,
    SMMetricType,
    SMRule,
    SMSubnetSegment,
    SMTestOutcome,
    SMTimeSegment,
)
from ftanalyzer.reports import StatisticalReport
from src.generator.interface import GeneratorStats
from ftanalyzer.counter import ContinuousCounter, TimeSeriesCounter, DiscreteCounter
from ftanalyzer.statistic_object import StatisticObject, SimState
from ftanalyzer.events import (
    Event,
    HostStatsEvent,
    OnePacketFlow,
    create_event_queue,
)
import sys


def is_debugger_active():
    return sys.gettrace() is not None


_TEMP_FILES = []


def _cleanup_temp_files():
    for path in _TEMP_FILES:
        try:
            Path(path).unlink()
        except FileNotFoundError:
            pass


# Register only once
atexit.register(_cleanup_temp_files)


class StatisticalModel:
    """
    StatisticalModel reads flows obtained from a network probe and compares them with a provided reference.

    Both data sources must be CSV files with the following columns (order does not matter):
        START_TIME: time of the first observed packet in the flow (UTC timestamp in milliseconds)
        END_TIME: time of the last observed packet in the flow (UTC timestamp in milliseconds)
        PROTOCOL: protocol number defined by IANA
        SRC_IP: source IP address (IPv4 or IPv6)
        DST_IP: destination IP address (IPv4 or IPv6)
        SRC_PORT: source port number (can be 0 if the flow does not contain TCP or UDP)
        DST_PORT: destination port number (can be 0 if the flow does not contain TCP or UDP)
        PACKETS: number of transferred packets
        BYTES: number of transferred bytes (IP headers + payload)

    The model can merge flows with the same flow key (SRC_IP, DST_IP, SRC_PORT, DST_PORT, PROTOCOL).
    Merging is allowed only if the flow key is unique in the reference data.
    Statistical analysis can be performed on the whole data or on specific subsets (segments) defined by IP subnets or time intervals.

    Attributes:
        _flows (pandas.DataFrame): Flow records from a network probe.
        _ref (pandas.DataFrame): Reference flow records.
    _fast_model : ft_fast_analyzer.StatisticalModel, optional
        Statistical model from the ft_fast_analyzer module if available and usable.
    """

    # pylint: disable=too-few-public-methods
    TIME_EPSILON = 1000
    FLOW_KEY = ["SRC_IP", "DST_IP", "SRC_PORT", "DST_PORT", "PROTOCOL"]
    DIR_INVARIANT_FLOW_KEY = [
        "INV_SRC_IP",
        "INV_DST_IP",
        "INV_SRC_PORT",
        "INV_DST_PORT",
        "PROTOCOL",
    ]
    CSV_COLUMN_TYPES = {
        "START_TIME": np.uint64,
        "END_TIME": np.uint64,
        "PROTOCOL": np.uint8,
        "SRC_IP": str,
        "DST_IP": str,
        "SRC_PORT": np.uint16,
        "DST_PORT": np.uint16,
        "PACKETS": np.uint64,
        "BYTES": np.uint64,
        "EXPORT_TIME": np.uint64,
        "SEQ_NUMBER": np.uint32,
        "MSG_LENGTH": np.uint64,
    }
    CSV_COLUMN_TYPES_NULLABLE = {
        "START_TIME": "UInt64",
        "END_TIME": "UInt64",
        "PROTOCOL": "UInt8",
        "SRC_IP": str,
        "DST_IP": str,
        "SRC_PORT": "UInt16",
        "DST_PORT": "UInt16",
        "PACKETS": "UInt64",
        "BYTES": "UInt64",
        "EXPORT_TIME": "UInt64",
        "SEQ_NUMBER": "UInt32",
        "MSG_LENGTH": "UInt64",
    }

    AGGREGATE_FLOWS = {
        "START_TIME": "min",
        "END_TIME": "max",
        "PACKETS": "sum",
        "BYTES": "sum",
        "EXPORT_TIME": "first",
        "SEQ_NUMBER": "first",
        "MSG_LENGTH": "first",
    }

    def __init__(
        self,
        flows: str,
        reference: Union[str, pd.DataFrame],
        stats: GeneratorStats,
        log_dir: PathLike,
        host_stats: PathLike,
        merge: bool = False,
        use_statistical_counter: bool = False,
        biflows_ts_correction: bool = False,
        inactive_timeout: int = 50,
    ) -> None:
        """
        Read provided files and convert them to data frames.

        Args:
            flows (str): Path to CSV with flow records from a network probe.
            reference (str or pd.DataFrame): Path to CSV or DataFrame with reference flow records.
            stats (GeneratorStats): Generator statistics object.
            log_dir (PathLike): Directory for logs.
            host_stats (PathLike): Path to host statistics file.
            merge (bool): Merge probe flows with the same flow key. Only allowed if flow key is unique in reference data.
            use_statistical_counter (bool): Use statistical counter objects.
            biflows_ts_correction (bool): Set True if probe exports biflows and precision model is used; corrects timestamps in reverse direction flows.
            inactive_timeout (int): Timeout for inactive flows (seconds).

        Raises:
            SMException: Unable to process provided files.
        """

        if fast_analyzer_available() and not merge and not biflows_ts_correction:
            self._fast_model = create_statistical_model(
                flows, reference, stats.start_time
            )
            return

        # fallback to python analyzer implementation
        self._fast_model = None

        self._log_dir = log_dir

        if isinstance(reference, str):
            self._ref_path = reference
        else:
            self._ref_path = tempfile.NamedTemporaryFile(
                delete=False, prefix="tmp_ref", suffix=".csv"
            ).name
            reference.to_csv(
                self._ref_path,
                index=False,
            )
            reference = pd.DataFrame(columns=self.CSV_COLUMN_TYPES.keys())

        self._generator_stats: GeneratorStats = stats
        self._flows_ip_addresses_converted = False
        self._ref_ip_addresses_converted = isinstance(reference, pd.DataFrame)
        self._stat_counter = use_statistical_counter
        self._inactive_timeout = inactive_timeout
        self._flows_path = flows

        if merge:
            self._merge_flows(biflows_ts_correction)

        if use_statistical_counter:
            # statistic objects
            self._executor = (
                ThreadPoolExecutor() if is_debugger_active() else ProcessPoolExecutor()
            )
            self._future_sim = self._executor.submit(
                self._run_sim,
                host_stats,
                self._generator_stats.start_time,
                self._generator_stats.end_time,
                inactive_timeout,
                self._flows_path,
            )

            self._future_ref = self._executor.submit(
                self._run_sim,
                "",
                self._generator_stats.start_time,
                self._generator_stats.end_time,
                inactive_timeout,
                self._ref_path,
            )
        else:
            self._executor = None
            self._future_ref = None
            self._future_sim = None

    @staticmethod
    def prepare_flows_file(path: os.PathLike, generator_stats: GeneratorStats):
        """initial read of flows.csv in chunks
        replaces faulty values and filters out some flows

        Args:
            path (os.PathLike): _description_

        Returns:
            _type_: _description_
        """
        out_file = tempfile.NamedTemporaryFile(
            delete=False, prefix="tmp_flows", suffix=".csv"
        ).name
        first_write = True
        logging.getLogger().debug("reading file with flows=%s", path)
        # ports could be empty in flows with protocol like ICMP
        # open output file once to avoid repeated open/close syscalls
        with open(out_file, "w", newline="", encoding="ascii") as csvf:
            for chunk in pd.read_csv(
                path, dtype=StatisticalModel.CSV_COLUMN_TYPES_NULLABLE, chunksize=10_000
            ):
                # fill missing values in-place to avoid extra copy
                chunk.fillna(
                    {
                        "START_TIME": 0,
                        "END_TIME": 0,
                        "PROTOCOL": 0,
                        "SRC_IP": "",
                        "DST_IP": "",
                        "SRC_PORT": 0,
                        "DST_PORT": 0,
                        "PACKETS": 0,
                        "BYTES": 0,
                        "EXPORT_TIME": 0,
                        "SEQ_NUMBER": 0,
                        "MSG_LENGTH": 0,
                    },
                    inplace=True,
                )

                chunk = chunk.astype(StatisticalModel.CSV_COLUMN_TYPES)

                # zero ICMP ports (vectorized)
                StatisticalModel._zero_icmp_ports(chunk)

                # build a single combined mask to apply all filters in one go
                mask = np.ones(len(chunk), dtype=bool)
                if generator_stats.start_time > 0:
                    mask &= chunk["START_TIME"] >= generator_stats.start_time - 500

                # multicast filters: ipv4 and ipv6
                # DST_IP might be empty string for some rows (we set that above), so startswith is safe
                mask &= chunk["DST_IP"] != "255.255.255.255"
                mask &= ~chunk["DST_IP"].str.startswith("ff02:")

                filtered = chunk.loc[mask]

                # write filtered chunk to CSV using the open file handle
                filtered.to_csv(csvf, index=False, header=first_write)
                first_write = False

        os.remove(path)
        return out_file

    @staticmethod
    def _run_sim(
        host_stats: GeneratorStats,
        start_time: np.uint64,
        end_time: np.uint64,
        inactive_timeout: int,
        flows_file: PathLike,
    ):
        output_dir = tempfile.mkdtemp()

        sim = SimState(start_time)
        statistic_objects, metric_to_obj = setup_statsitic_objects(
            sim, start_time, end_time, inactive_timeout
        )
        event_queue = create_event_queue(
            flows_file, host_stats, inactive_timeout, output_dir
        )
        process_events(event_queue, statistic_objects, metric_to_obj, sim)

        shutil.rmtree(output_dir, ignore_errors=True)

        return statistic_objects

    def __del__(self):
        try:
            Path(self._flows_path).unlink()
            Path(self._ref_path).unlink()
        except FileNotFoundError:
            pass

    def _load_flows_df(self):
        return pd.read_csv(
            self._flows_path, engine="pyarrow", dtype=self.CSV_COLUMN_TYPES
        )

    def _load_ref_df(self):
        return pd.read_csv(
            self._ref_path, engine="pyarrow", dtype=self.CSV_COLUMN_TYPES
        )

    @staticmethod
    def _zero_icmp_ports(df: pd.DataFrame):
        icmp_protocols = [1, 58]  # ICMP and ICMPv6
        icmp_mask = df["PROTOCOL"].isin(icmp_protocols)
        df.loc[icmp_mask, ["SRC_PORT", "DST_PORT"]] = 0

    def validate(
        self, rules: List[SMRule], check_complement: bool = False
    ) -> StatisticalReport:
        """
        Evaluate data in the statistical model based on the provided evaluation rules.

        Args:
            rules (list): Evaluation rules for the analysis.
            check_complement (bool): If True, checks if complement of segments in rules is empty.

        Returns:
            StatisticalReport: Report containing results of performed tests.

        Raises:
            SMException: If duplicated metrics are present in a single validation rule.
        """
        start = time.time()

        # run _validate_helper in parallel on different files
        self._future_flow_values = self._executor.submit(
            _validate_helper, self._flows_path, rules, self._generator_stats
        )
        self._future_ref_values = self._executor.submit(
            _validate_helper, self._ref_path, rules, self._generator_stats, is_ref=True
        )
        flow_values, all_flow_masks = self._future_flow_values.result()

        # run _validate_helper in parallel on different files
        self._future_flow_values = self._executor.submit(
            _validate_helper, self._flows_path, rules, self._generator_stats
        )
        self._future_ref_values = self._executor.submit(
            _validate_helper, self._ref_path, rules, self._generator_stats, is_ref=True
        )
        flow_values, all_flow_masks = self._future_flow_values.result()

        if self._fast_model is not None:
            return validate_statistical_model(self._fast_model, rules, check_complement)

        report = StatisticalReport(self._log_dir)
        if check_complement:
            complement_rules = [SMRule(SMMetricType.__members__.values())]
            self._future_complement_values = self._executor.submit(
                _validate_helper,
                self._flows_path,
                complement_rules,
                self._generator_stats,
                complement=True,
                flow_masks=all_flow_masks,
            )

        ref_values, _ = self._future_ref_values.result()

        for rule, flow_dict, ref_dict in zip(rules, flow_values, ref_values):
            for metric in rule.metrics:
                value = flow_dict[metric.key]
                reference = ref_dict[metric.key]
                report.add_test(
                    SMTestOutcome(
                        metric,
                        rule.segment,
                        value,
                        reference,
                        round(abs(int(value) - int(reference)) / reference, 4),
                    )
                )

        if check_complement:
            complement_values, _ = self._future_complement_values.result()

            rule = rules[0]
            values = complement_values[0]

            for metric in rule.metrics:
                reference = 0
                value = values[metric.key]
                report.add_test(
                    SMTestOutcome(
                        metric,
                        "COMPLEMENT OF SEGMENTS",
                        value,
                        reference,
                        0 if value == reference else 1,
                    )
                )

        statistic_objects = self._future_sim.result() if self._future_sim else dict()
        ref_statistic_objects = (
            self._future_ref.result() if self._future_ref else dict()
        )
        if self._executor:
            self._executor.shutdown()
        for objects in zip(statistic_objects.values(), ref_statistic_objects.values()):
            report.add_statistic_object(*objects)

        end = time.time()
        logging.getLogger().info(
            "Statistically validated in %.2f seconds.", (end - start)
        )

        return report

    def _filter_multicast(self, flows: pd.DataFrame):
        # ipv4
        flows.drop(flows[flows["DST_IP"] == "255.255.255.255"].index, inplace=True)

        # ipv6
        flows.drop(flows[flows["DST_IP"].str.startswith("ff02:")].index, inplace=True)

    def _merge_flows(self, biflows_ts_correction: bool) -> None:
        """
        Merge flows with the same flow key.
        Allowed only if the flow key is unique in the reference data.
        Add 'FLOW_COUNT' column to the data from probe to indicate how many flows were merged together.

        Parameters
        ----------
        biflows_ts_correction : bool
            Value should be True when probe exporting biflows and precision model is used.
            Timestamps in reverse direction flows is corrected.
        """

        ref_df = self._load_ref_df()
        assert len(ref_df.index) == ref_df.groupby(self.FLOW_KEY).ngroups, (
            "Cannot merge flows, duplicated key."
        )
        del ref_df

        flows_df = self._load_flows_df()
        flows = flows_df.groupby(self.FLOW_KEY).aggregate(self.AGGREGATE_FLOWS)
        flows["FLOW_COUNT"] = flows_df.groupby(self.FLOW_KEY).size()
        flows_df = flows.reset_index()

        if biflows_ts_correction:
            # correct timestamps in reverse direction of flows originating from biflows
            # using direction invariant flow key
            flows = flows_df

            swap_cond = flows["SRC_IP"] > flows["DST_IP"]
            flows["INV_SRC_IP"] = np.where(swap_cond, flows["DST_IP"], flows["SRC_IP"])
            flows["INV_DST_IP"] = np.where(swap_cond, flows["SRC_IP"], flows["DST_IP"])
            flows["INV_SRC_PORT"] = np.where(
                swap_cond, flows["DST_PORT"], flows["SRC_PORT"]
            )
            flows["INV_DST_PORT"] = np.where(
                swap_cond, flows["SRC_PORT"], flows["DST_PORT"]
            )

            grouped = flows.groupby(self.DIR_INVARIANT_FLOW_KEY)
            flows["START_TIME"] = grouped["START_TIME"].transform("min")
            flows["END_TIME"] = grouped["END_TIME"].transform("max")

            flows_df = flows.loc[:, list(self.CSV_COLUMN_TYPES.keys()) + ["FLOW_COUNT"]]

        flows_df.to_csv(self._flows_path, index=False)

    @staticmethod
    def _convert_ip_addresses(flows_df: pd.DataFrame) -> None:
        """Convert str ip addresses to objects (ipaddress library) in DataFrames."""

        logging.getLogger().debug("Start applying ip_address...")
        start = time.time()
        with PandasMultiprocessingHelper() as pool:
            pool.apply(
                flows_df,
                [
                    ("SRC_IP", ipaddress.ip_address, []),
                    ("DST_IP", ipaddress.ip_address, []),
                ],
            )
        end = time.time()
        logging.getLogger().debug("IP address applied in %.2f seconds.", (end - start))

    @staticmethod
    def _filter_segment(
        segment: Optional[Union[SMSubnetSegment, SMTimeSegment]],
        flows_df: pd.DataFrame,
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """Create subsets of data frames based on the provided segment.

        Parameters
        ----------
        segment : SMSubnetSegment, SMTimeSegment, None
            Segment to be used to create subsets.

        Returns
        ------
        tuple
            subset of flows acquired from the probe, subset of reference flows, used flows mask
        """

        if isinstance(segment, SMSubnetSegment):
            StatisticalModel._convert_ip_addresses(flows_df)
            return StatisticalModel._filter_subnet_segment(segment)

        if isinstance(segment, SMTimeSegment):
            return StatisticalModel._filter_time_segment(segment)

        assert segment is None
        return flows_df, pd.Series([True] * flows_df.shape[0])

    @staticmethod
    def _filter_subnet_segment(
        segment: SMSubnetSegment, flows_df: pd.DataFrame
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """Create subsets of data frames based on subnets.

        Parameters
        ----------
        segment : SMSubnetSegment
            Segment to be used to create subsets.

        Returns
        ------
        tuple
            subset of flows acquired from the probe, subset of reference flows, used flows mask
        """

        subnet_source = (
            ipaddress.ip_network(segment.source) if segment.source is not None else None
        )
        subnet_dest = (
            ipaddress.ip_network(segment.dest) if segment.dest is not None else None
        )

        if subnet_source is not None and subnet_dest is not None:
            if segment.bidir:
                mask_flow = (
                    flows_df["SRC_IP"].apply(lambda x: x in subnet_source)
                    & flows_df["DST_IP"].apply(lambda x: x in subnet_dest)
                ) | (
                    flows_df["SRC_IP"].apply(lambda x: x in subnet_dest)
                    & flows_df["DST_IP"].apply(lambda x: x in subnet_source)
                )
            else:
                mask_flow = flows_df["SRC_IP"].apply(
                    lambda x: x in subnet_source
                ) & flows_df["DST_IP"].apply(lambda x: x in subnet_dest)
        elif subnet_source is not None:
            if segment.bidir:
                mask_flow = flows_df["SRC_IP"].apply(
                    lambda x: x in subnet_source
                ) | flows_df["DST_IP"].apply(lambda x: x in subnet_source)
            else:
                mask_flow = flows_df["SRC_IP"].apply(lambda x: x in subnet_source)
        else:
            if segment.bidir:
                mask_flow = flows_df["SRC_IP"].apply(
                    lambda x: x in subnet_dest
                ) | flows_df["DST_IP"].apply(lambda x: x in subnet_dest)
            else:
                mask_flow = flows_df["DST_IP"].apply(lambda x: x in subnet_dest)

        return (
            flows_df[mask_flow].reset_index(drop=True),
            mask_flow,
        )

    @staticmethod
    def _filter_time_segment(
        segment: SMTimeSegment, flows_df: pd.DataFrame
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """Create subsets of data frames based on time interval.

        Parameters
        ----------
        segment : SMTimeSegment
            Segment to be used to create subsets.

        Returns
        ------
        tuple
            subset of flows acquired from the probe, subset of reference flows, used flows mask
        """

        start_time = end_time = None
        if segment.start is not None:
            start_time = int(segment.start.timestamp() * 1000)

        if segment.end is not None:
            end_time = int(segment.end.timestamp() * 1000)

        if start_time is not None and end_time is not None:
            mask_flow = flows_df["START_TIME"].apply(
                lambda x: x >= start_time
            ) & flows_df["END_TIME"].apply(lambda x: x <= end_time)
        elif start_time is not None:
            mask_flow = flows_df["START_TIME"].apply(lambda x: x >= start_time)
        else:
            mask_flow = flows_df["END_TIME"].apply(lambda x: x <= end_time)

        return (
            flows_df[mask_flow].reset_index(drop=True),
            mask_flow,
        )


def setup_statsitic_objects(
    sim: SimState, start_time: np.uint64, end_time: np.uint64, inactive_timeout: int
) -> tuple[dict[str, StatisticObject], dict[str, List[str]]]:
    """Create two dicts.
    The first one maps strings to StatisticObjects.
    The second one maps a metric name to a list of strings, that are from the first dict

    Returns:
        tuple[dict[str, StatisticObject], dict[str, List[str]]]: the two dicts in a tuple
    """
    start_time_offset = np.uint64(start_time + 10000)  # ten seconds transient phase
    end_time_offset = np.uint64(end_time - 10000)  # ten seconds end phase
    statistic_objects: dict[str, StatisticObject] = {
        "ct_data_rate": ContinuousCounter(
            "data rate in Gb/s",
            sim,
            1 / (10**9),
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "ct_packet_rate": ContinuousCounter(
            "packets per second",
            sim,
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "ct_flow_count": ContinuousCounter(
            "active flows (in cache)",
            sim,
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "ct_active_flows": ContinuousCounter(
            "active flows",
            sim,
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "ct_cpu_usage": ContinuousCounter(
            "CPU usage in percent",
            sim,
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "ct_ram_usage": ContinuousCounter(
            "RAM Usage in GiB",
            sim,
            factor=1 / 1024**2,  # convert KiB to GiB
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "ct_export_rate_f": ContinuousCounter(
            "Export Rate in flows/s",
            sim,
            measure_start_time=start_time_offset + inactive_timeout * 1000,
            measure_end_time=end_time,
        ),
        "ct_export_rate_p": ContinuousCounter(
            "Export Rate in packets/s",
            sim,
            measure_start_time=start_time_offset + inactive_timeout * 1000,
            measure_end_time=end_time,
        ),
        "ct_flows_per_export_packet": ContinuousCounter(
            "Flows per exported Packet in flows/packet",
            sim,
            measure_start_time=start_time_offset + inactive_timeout * 1000,
            measure_end_time=end_time,
        ),
        "dt_flows_active_time": DiscreteCounter("Flow Duration Active"),
        "dt_flows_cache_time": DiscreteCounter("Flow Duration in Cache"),
        "tsc_data_rate": TimeSeriesCounter(
            "data rate in Gb/s",
            sim,
            start_time_offset,
            end_time_offset,
            1 / (10**9),
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "tsc_packet_rate": TimeSeriesCounter(
            "packets per second",
            sim,
            start_time,
            end_time,
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "tsc_flow_count": TimeSeriesCounter(
            "active flows (in cache)",
            sim,
            start_time,
            end_time,
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "tsc_active_flows": TimeSeriesCounter(
            "active flows",
            sim,
            start_time,
            end_time,
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "tsc_cpu_usage": TimeSeriesCounter(
            "CPU usage in percent",
            sim,
            start_time,
            end_time,
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "tsc_mem_usage": TimeSeriesCounter(
            "RAM Usage in GiB",
            sim,
            start_time,
            end_time,
            factor=1 / (1024**2),  # convert KiB to GiB
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "tsc_export_rate_f": TimeSeriesCounter(
            "Export Rate in flows/s",
            sim,
            start_time,
            end_time,
            measure_start_time=start_time_offset + inactive_timeout * 1000,
            measure_end_time=end_time,
        ),
        "tsc_export_rate_p": TimeSeriesCounter(
            "Export Rate in packets/s",
            sim,
            start_time,
            end_time,
            measure_start_time=start_time_offset + inactive_timeout * 1000,
            measure_end_time=end_time,
        ),
        "tsc_flows_per_export_packet": TimeSeriesCounter(
            "Flows per exported Packet in flows/packet",
            sim,
            start_time,
            end_time,
            measure_start_time=start_time_offset + inactive_timeout * 1000,
            measure_end_time=end_time,
        ),
        "tsc_flows_active_time": TimeSeriesCounter(
            "Flow Duration Active",
            sim,
            start_time,
            end_time,
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "tsc_flows_cache_time": TimeSeriesCounter(
            "Flow Duration in Cache",
            sim,
            start_time,
            end_time,
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
    }

    metric_mapping: dict[str, List[str]] = {
        "data_rate": ["ct_data_rate", "ct_data_rate_bibit", "tsc_data_rate"],
        "packet_rate": ["ct_packet_rate", "tsc_packet_rate"],
        "flow_count": ["ct_flow_count", "tsc_flow_count"],
        "active_flows": ["ct_active_flows", "tsc_active_flows"],
        "percent_CPU": ["ct_cpu_usage", "tsc_cpu_usage"],
        "total_MEM": ["ct_ram_usage", "tsc_mem_usage"],
        "export_rate_f": ["ct_export_rate_f", "tsc_export_rate_f"],
        "export_rate_p": ["ct_export_rate_p", "tsc_export_rate_p"],
        "export_flows_p_packet": [
            "tsc_flows_per_export_packet",
            "ct_flows_per_export_packet",
        ],
        "active_time": ["dt_flows_active_time", "tsc_flows_active_time"],
        "cache_time": ["dt_flows_cache_time", "tsc_flows_cache_time"],
    }

    return (statistic_objects, metric_mapping)


def _flush_event_data(
    one_packet_events: List[OnePacketFlow],
    current_data_rate: int,
    current_packet_rate: int,
    current_flows: int,
    active_flows: int,
    statistic_objects: dict[str, StatisticObject],
    metric_mapping: dict[str, str],
    duration_s: float,
    simultaneous_events: List[Event],
    sim: SimState,
    last_export: int,
):
    # aggregate OnePacketFlow events within this window
    one_packet_data_rate = sum(e.bytes for e in one_packet_events) * 8 / duration_s
    one_packet_packet_rate = sum(e.packets for e in one_packet_events) / duration_s

    # Compose final rates
    total_data_rate = one_packet_data_rate + current_data_rate
    total_packet_rate = one_packet_packet_rate + current_packet_rate

    update_statistic_objects(
        statistic_objects,
        metric_mapping,
        data_rate=total_data_rate,
        packet_rate=total_packet_rate,
        flow_count=current_flows,
        active_flows=active_flows,
    )

    export_events: List[ExportEvent] = [
        e for e in simultaneous_events if isinstance(e, ExportEvent)
    ]
    since_last_export: np.uint64 = sim.get_time_diff(last_export)
    if export_events:
        time_since_export_s = sim.convert_to_seconds(since_last_export)
        export_flows = sum(e.flows for e in export_events)
        export_bytes = sum(e.bytes for e in export_events)
        export_packets = len(export_events)
        export_flows_p_packet = export_flows / export_packets
        update_statistic_objects(
            statistic_objects,
            metric_mapping,
            export_rate_f=export_flows / time_since_export_s,
            export_rate_b=export_bytes / time_since_export_s,
            export_rate_p=export_packets / time_since_export_s,
            export_flows_p_packet=export_flows_p_packet,
        )
        last_export = sim.get_time()
    elif since_last_export >= 1000:
        # use 0 as datapoint every second to register absence of exports
        update_statistic_objects(
            statistic_objects,
            metric_mapping,
            export_rate_f=0,
            export_rate_b=0,
            export_rate_p=0,
            export_flows_p_packet=0.0,
        )
        last_export = sim.get_time()

    host_stats_event: HostStatsEvent = next(
        (e for e in simultaneous_events if isinstance(e, HostStatsEvent)),
        None,
    )
    if host_stats_event:
        update_statistic_objects(
            statistic_objects, metric_mapping, **host_stats_event.row._asdict()
        )

    for event in simultaneous_events:
        if isinstance(event, OnePacketFlow) or isinstance(event, FlowEndEvent):
            update_statistic_objects(
                statistic_objects,
                metric_mapping,
                active_time=event.active_time,
                cache_time=event.cache_time,
            )

    return last_export


def process_events(
    event_queue: Iterable[Event],
    statistic_objects: dict[str, StatisticObject],
    metric_mapping: dict[str, List[str]],
    sim: SimState,
) -> None:
    """
    Process a stream of flow events, calculating data rates and packet rates
    over event-driven time windows.

    OnePacketFlow events are aggregated into the current time window until
    a non-zero duration interval is reached. Multiple events at the same
    timestamp are processed together to avoid zero-duration artifacts.
    """

    one_packet_events: list[OnePacketFlow] = []
    current_data_rate = 0
    current_packet_rate = 0
    current_flows = 0
    active_flows = 0

    # Prime the iterator
    event_iter = iter(event_queue)
    try:
        current_event = next(event_iter)
    except StopIteration:
        return  # No events to process

    last_time: np.uint64 = sim.get_time()
    last_export: np.uint64 = sim.get_time() // 1000 * 1000
    sim.set_time(current_event.time)

    simultaneous_events = [current_event]

    for event in event_iter:
        if event.time == sim.get_time():
            simultaneous_events.append(event)
            continue

        # Compute the duration between the last time and the current group of events
        duration_ms = sim.get_time_diff(last_time)
        duration_s = sim.convert_to_seconds(duration_ms)

        # Only advance stats if time progressed
        if (
            duration_ms > 0
            and not all_instance_of(simultaneous_events, OnePacketFlow)
            or duration_ms > 100
        ):
            last_export = _flush_event_data(
                one_packet_events,
                current_data_rate,
                current_packet_rate,
                current_flows,
                active_flows,
                statistic_objects,
                metric_mapping,
                duration_s,
                simultaneous_events,
                sim,
                last_export,
            )
            # reset one-packet events after processing
            one_packet_events.clear()
            # move forward in time
            last_time = sim.get_time()

        # apply each event's effect to current rates
        for e in simultaneous_events:
            if isinstance(e, HostStatsEvent):
                pass
            elif isinstance(e, ExportEvent):
                current_flows -= e.flows
            elif isinstance(e, OnePacketFlow):
                one_packet_events.append(e)
                current_flows += e.flows
            else:
                current_data_rate += e.data_rate
                current_packet_rate += e.packet_rate
                active_flows += e.flows
                if isinstance(e, FlowStartEvent):
                    current_flows += e.flows

        current_data_rate = max(0, current_data_rate)
        current_packet_rate = max(0, current_packet_rate)

        sim.set_time(event.time)
        simultaneous_events = [event]

    # Final flush
    duration_ms = sim.get_time_diff(last_time)
    duration_s = sim.convert_to_seconds(duration_ms)

    if duration_ms > 0:
        _flush_event_data(
            one_packet_events,
            current_data_rate,
            current_packet_rate,
            current_flows,
            active_flows,
            statistic_objects,
            metric_mapping,
            duration_s,
            simultaneous_events,
            sim,
            last_export,
        )


def update_statistic_objects(
    statistic_objects: dict[str, StatisticObject],
    metric_mapping: dict[str, List[str]],
    **kwargs: dict | None,
):
    for key, rate in kwargs.items():
        if rate is None:
            continue
        stat_obj_names = metric_mapping.get(key, [])
        for stat_obj_name in stat_obj_names:
            stat_obj = statistic_objects.get(stat_obj_name)
            if stat_obj is not None:
                stat_obj.count(rate)


def all_instance_of(iterable: Iterable, cls):
    """
    Check if all elements in `iterable` are instances of `cls`.
    """
    return all(isinstance(item, cls) for item in iterable)


def _validate_helper(
    flows_file,
    rules: List[SMRule],
    generator_stats: GeneratorStats,
    chunksize=10_000,
    is_ref=False,
    complement=False,
    flow_masks=[],
):
    all_flow_masks = {}
    values: List[dict] = []
    start_time = float("inf")
    end_time = float("-inf")

    for chunk in pd.read_csv(
        flows_file, dtype=StatisticalModel.CSV_COLUMN_TYPES, chunksize=chunksize
    ):
        start_time = min(start_time, chunk["START_TIME"].min())
        end_time = max(end_time, chunk["END_TIME"].max())

        if complement:
            chunk = chunk[~(reduce(operator.or_, flow_masks))].reset_index(drop=True)
        for i, rule in zip(range(len(rules)), rules):
            if not complement:
                flows, mask = StatisticalModel._filter_segment(rule.segment, chunk)
                all_flow_masks.update(mask)
            else:
                flows = chunk

            values_dict = values[i] if i < len(values) else dict()

            # Check duplicated metrics.
            if len({m.key for m in rule.metrics}) != len(rule.metrics):
                raise SMException(f"Rule contains duplicated metrics: {rule.metrics}")

            for metric in rule.metrics:
                match metric.key:
                    case SMMetricType.FLOWS:
                        value = len(flows.index)
                    case SMMetricType.MBPS:
                        value = 0  # later calculated
                    case SMMetricType.PPS:
                        value = 0  # later calculated
                    case SMMetricType.DURATION:
                        value = 0  # later calculated
                    case _:
                        value = flows[metric.key.value].sum()

                if metric.key in values_dict:
                    values_dict[metric.key] += value
                else:
                    values_dict[metric.key] = value

            if len(values) <= i:
                values.append(values_dict)
            else:
                values[i] = values_dict

    for values_dict in values:
        if is_ref:
            duration = (
                generator_stats.end_time - generator_stats.start_time + 1
            ) / 1000
        else:
            duration = (end_time - start_time + 1) / 1000
        values_dict[SMMetricType.DURATION] = duration
        values_dict[SMMetricType.MBPS] = (
            values_dict[SMMetricType.BYTES] / duration / 10**6
        )
        values_dict[SMMetricType.PPS] = values_dict[SMMetricType.PACKETS] / duration

    return values, all_flow_masks
