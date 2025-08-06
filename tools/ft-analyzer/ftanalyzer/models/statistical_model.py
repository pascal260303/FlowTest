"""
Author(s): Tomas Jansky <Tomas.Jansky@progress.com>

Copyright: (C) 2023 Flowmon Networks a.s.
SPDX-License-Identifier: BSD-3-Clause

"""

import atexit
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import gc
import ipaddress
import logging
import operator
from os import PathLike
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
from ftanalyzer.events.events import ExportEvent
from ftanalyzer.models.sm_data_types import (
    SMException,
    SMMetric,
    SMMetricType,
    SMRule,
    SMSubnetSegment,
    SMTestOutcome,
    SMTimeSegment,
)
from ftanalyzer.reports import StatisticalReport
from src.generator.interface import GeneratorStats
from ftanalyzer.counter import ContinuousCounter, TimeSeriesCounter
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
    """Statistical model reads flows obtained from a network probe and compares them with a provided reference.

    Both data sources must be CSV files with the following columns (order of columns does not matter):
        START_TIME: time of the first observed packet in the flow (UTC timestamp in milliseconds)
        END_TIME: time of the last observed packet in the flow (UTC timestamp in milliseconds)
        PROTOCOL: protocol number defined by IANA
        SRC_IP: source IP address (IPv4 or IPv6)
        DST_IP: destination IP address (IPv4 or IPv6)
        SRC_PORT: source port number (can be 0 if the flow does not contain TCP or UDP protocol)
        DST_PORT: destination port number (can be 0 if the flow does not contain TCP or UDP protocol)
        PACKETS: number of transferred packets
        BYTES: number of transferred bytes (IP headers + payload)

    Statistical model is able to merge flows with the same flow key (SRC_IP, DST_IP, SRC_PORT, DST_PORT, PROTOCOL).
    Merging flows is allowed only if the flow key is unique in the reference data.
    The model is able to perform statistical analysis of the provided data to determine how much it differs from the
    reference. Every analysis can be done either with the whole data or with a specific subset (called "segment")
    which can be specified either by IP subnets or time intervals.

    Attributes
    ----------
    _flows : pandas.DataFrame
        Flow records acquired from a network probe.
    _ref : pandas.DataFrame
        Flow records acting as a reference.
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
        """Read provided files and converts it to data frames.

        Parameters
        ----------
        flows : str
            Path to a CSV containing flow records acquired from a network probe.
        reference : str or pd.DataFrame
            Path to a CSV containing flow records acting as a reference.
            Or DataFrame in corresponding format.
        start_time : int
            Treat times in the reference file as offsets (in milliseconds) from the provided start time.
            UTC timestamp in milliseconds.
        merge : bool
            Merge probe flows with the same flow key (SRC_IP, DST_IP, SRC_PORT, DST_PORT, PROTOCOL).
            Merging flows is allowed only if the flow key is unique in the reference data.
        biflows_ts_correction : bool
            Value should be True when probe exporting biflows and precision model is used.
            Timestamps in reverse direction flows are corrected.

        Raises
        ------
        SMException
            Unable to process provided files.
        """

        if fast_analyzer_available() and not merge and not biflows_ts_correction:
            self._fast_model = create_statistical_model(flows, reference, start_time)
            return

        # fallback to python analyzer implementation
        self._fast_model = None

        self._log_dir = log_dir

        try:
            logging.getLogger().debug("reading file with flows=%s", flows)
            # ports could be empty in flows with protocol like ICMP
            self._flows_path = flows
            flows = pd.read_csv(flows, engine="pyarrow", dtype=self.CSV_COLUMN_TYPES)
            flows["SRC_PORT"] = flows["SRC_PORT"].fillna(0)
            flows["DST_PORT"] = flows["DST_PORT"].fillna(0)
            self._flows: pd.DataFrame = flows.astype(self.CSV_COLUMN_TYPES)

            if isinstance(reference, str):
                self._ref = None
                self._ref_path = reference
            else:
                self._ref = reference
        except Exception as err:
            raise SMException("Unable to read file with flows.") from err

        self._zero_icmp_ports(self._flows)

        if stats.start_time > 0:
            # filter out flows that start before the start time with 500 ms tolerance
            self._flows = self._flows[
                self._flows["START_TIME"] >= stats.start_time - 500
            ]

        # if stats.end_time > 0:
        #    # filter out flows that start before the end time
        #    self._flows = self._flows[self._flows["START_TIME"] <= stats.end_time]

        self._filter_multicast()

        if merge:
            self._merge_flows(biflows_ts_correction)

        # write dataframes back to file and read later when needed
        if not (hasattr(self, "_flows_path") and self._flows_path):
            self._flows_path = tempfile.NamedTemporaryFile(
                delete=False, suffix=".csv"
            ).name
        self._flows.to_csv(self._flows_path, index=False)
        del self._flows
        gc.collect()

        _TEMP_FILES.append(self._flows_path)

        if not (hasattr(self, "_ref_path") and self._ref_path):
            self._ref_path = tempfile.NamedTemporaryFile(
                delete=False, suffix=".csv"
            ).name
        self._ref.to_csv(self._ref_path, index=False)
        del self._ref
        gc.collect()

        _TEMP_FILES.append(self._ref_path)

        self._generator_stats: GeneratorStats = stats
        self._flows_ip_addresses_converted = False
        self._ref_ip_addresses_converted = isinstance(reference, pd.DataFrame)
        self._stat_counter = use_statistical_counter
        self._inactive_timeout = inactive_timeout

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
        event_queue = create_event_queue(flows_file, host_stats, output_dir)
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

    def _zero_icmp_ports(self, df: pd.DataFrame):
        icmp_protocols = [1, 58]  # ICMP and ICMPv6
        icmp_mask = df["PROTOCOL"].isin(icmp_protocols)
        df.loc[icmp_mask, ["SRC_PORT", "DST_PORT"]] = 0

    def validate(
        self, rules: List[SMRule], check_complement: bool = False
    ) -> StatisticalReport:
        """Evaluate data in the statistical model based on the provided evaluation rules.

        Parameters
        ----------
        rules : list
            Evaluation rules which are used for the evaluation.
        check_complement : bool, optional
            Check if complement of segments in rules is empty. Default disabled.
            Subnet or time segments used in the rules are considered complete
            in this case.

        Returns
        ------
        StatisticalReport
            Report containing results of individual performed tests.

        Raises
        ------
        SMException
            When duplicated metrics in a single validation rule are present.
        """
        start = time.time()

        if self._fast_model is not None:
            return validate_statistical_model(self._fast_model, rules, check_complement)

        report = StatisticalReport(self._log_dir)
        all_flow_masks = []

        self._flows = self._load_flows_df()
        self._ref = self._load_ref_df()

        for rule in rules:
            flows, ref, mask_flow = self._filter_segment(rule.segment)
            all_flow_masks.append(mask_flow)

            # Check duplicated metrics.
            if len({m.key for m in rule.metrics}) != len(rule.metrics):
                raise SMException(f"Rule contains duplicated metrics: {rule.metrics}")

            duration = (flows["END_TIME"].max() - flows["START_TIME"].min() + 1) / 1000
            ref_duration = (
                self._generator_stats.end_time - self._generator_stats.start_time + 1
            ) / 1000

            for metric in rule.metrics:
                match metric.key:
                    case SMMetricType.FLOWS:
                        value = len(flows.index)
                        reference = len(ref.index)
                    case SMMetricType.MBPS:
                        value = (
                            flows[SMMetricType.BYTES.value].sum()
                            / duration
                            / pow(10, 6)
                        )
                        reference = (
                            ref[SMMetricType.BYTES.value].sum()
                            / ref_duration
                            / pow(10, 6)
                        )
                    case SMMetricType.PPS:
                        value = flows[SMMetricType.PACKETS.value].sum() / duration
                        reference = ref[SMMetricType.PACKETS.value].sum() / ref_duration
                    case SMMetricType.DURATION:
                        value = duration
                        reference = ref_duration
                    case _:
                        value = flows[metric.key.value].sum()
                        reference = ref[metric.key.value].sum()

                report.add_test(
                    SMTestOutcome(
                        metric,
                        rule.segment,
                        value,
                        reference,
                        abs(np.int64(value) - np.int64(reference)) / reference,
                    )
                )

        if check_complement:
            # pylint: disable=invalid-unary-operand-type
            flows = self._flows[~(reduce(operator.or_, all_flow_masks))].reset_index(
                drop=True
            )

            for metric in [
                SMMetric(SMMetricType.PACKETS, 0),
                SMMetric(SMMetricType.BYTES, 0),
            ]:
                value = flows[metric.key.value].sum()
                reference = 0

                report.add_test(
                    SMTestOutcome(
                        metric,
                        "COMPLEMENT OF SEGMENTS",
                        value,
                        reference,
                        0 if value == reference else 1,
                    )
                )

        statistic_objects = self._future_sim.result() if self._future_sim else {}
        ref_statistic_objects = self._future_ref.result() if self._future_ref else {}
        if self._executor:
            self._executor.shutdown()
        for objects in zip(statistic_objects.values(), ref_statistic_objects.values()):
            report.add_statistic_object(*objects)

        end = time.time()
        logging.getLogger().info(
            "Statistically validated in %.2f seconds.", (end - start)
        )

        return report

    def _filter_multicast(self):
        # ipv4
        self._flows = self._flows[self._flows["DST_IP"] != "255.255.255.255"]

        # ipv6
        self._flows = self._flows[~self._flows["DST_IP"].str.startswith("ff02::")]

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

        assert len(self._ref.index) == self._ref.groupby(self.FLOW_KEY).ngroups, (
            "Cannot merge flows, duplicated key."
        )

        flows = self._flows.groupby(self.FLOW_KEY).aggregate(self.AGGREGATE_FLOWS)
        flows["FLOW_COUNT"] = self._flows.groupby(self.FLOW_KEY).size()
        self._flows = flows.reset_index()

        if biflows_ts_correction:
            # correct timestamps in reverse direction of flows originating from biflows
            # using direction invariant flow key
            flows = self._flows

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

            self._flows = flows.loc[
                :, list(self.CSV_COLUMN_TYPES.keys()) + ["FLOW_COUNT"]
            ]

    def _convert_ip_addresses(self) -> None:
        """Convert str ip addresses to objects (ipaddress library) in DataFrames."""

        if self._flows_ip_addresses_converted and self._ref_ip_addresses_converted:
            return

        logging.getLogger().debug("Start applying ip_address...")
        start = time.time()
        with PandasMultiprocessingHelper() as pool:
            pool.apply(
                self._flows,
                [
                    ("SRC_IP", ipaddress.ip_address, []),
                    ("DST_IP", ipaddress.ip_address, []),
                ],
            )
            if not self._ref_ip_addresses_converted:
                # convert to object only when reference is loaded from CSV file
                pool.apply(
                    self._ref,
                    [
                        ("SRC_IP", ipaddress.ip_address, []),
                        ("DST_IP", ipaddress.ip_address, []),
                    ],
                )
        end = time.time()
        logging.getLogger().debug("IP address applied in %.2f seconds.", (end - start))

        self._flows_ip_addresses_converted, self._ref_ip_addresses_converted = (
            True,
            True,
        )

    def _filter_segment(
        self, segment: Optional[Union[SMSubnetSegment, SMTimeSegment]]
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series]:
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
            self._convert_ip_addresses()
            return self._filter_subnet_segment(segment)

        if isinstance(segment, SMTimeSegment):
            return self._filter_time_segment(segment)

        assert segment is None
        return self._flows, self._ref, pd.Series([True] * self._flows.shape[0])

    def _filter_subnet_segment(
        self, segment: SMSubnetSegment
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series]:
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
                    self._flows["SRC_IP"].apply(lambda x: x in subnet_source)
                    & self._flows["DST_IP"].apply(lambda x: x in subnet_dest)
                ) | (
                    self._flows["SRC_IP"].apply(lambda x: x in subnet_dest)
                    & self._flows["DST_IP"].apply(lambda x: x in subnet_source)
                )
                mask_ref = (
                    self._ref["SRC_IP"].apply(lambda x: x in subnet_source)
                    & self._ref["DST_IP"].apply(lambda x: x in subnet_dest)
                ) | (
                    self._ref["SRC_IP"].apply(lambda x: x in subnet_dest)
                    & self._ref["DST_IP"].apply(lambda x: x in subnet_source)
                )
            else:
                mask_flow = self._flows["SRC_IP"].apply(
                    lambda x: x in subnet_source
                ) & self._flows["DST_IP"].apply(lambda x: x in subnet_dest)
                mask_ref = self._ref["SRC_IP"].apply(
                    lambda x: x in subnet_source
                ) & self._ref["DST_IP"].apply(lambda x: x in subnet_dest)
        elif subnet_source is not None:
            if segment.bidir:
                mask_flow = self._flows["SRC_IP"].apply(
                    lambda x: x in subnet_source
                ) | self._flows["DST_IP"].apply(lambda x: x in subnet_source)
                mask_ref = self._ref["SRC_IP"].apply(
                    lambda x: x in subnet_source
                ) | self._ref["DST_IP"].apply(lambda x: x in subnet_source)
            else:
                mask_flow = self._flows["SRC_IP"].apply(lambda x: x in subnet_source)
                mask_ref = self._ref["SRC_IP"].apply(lambda x: x in subnet_source)
        else:
            if segment.bidir:
                mask_flow = self._flows["SRC_IP"].apply(
                    lambda x: x in subnet_dest
                ) | self._flows["DST_IP"].apply(lambda x: x in subnet_dest)
                mask_ref = self._ref["SRC_IP"].apply(
                    lambda x: x in subnet_dest
                ) | self._ref["DST_IP"].apply(lambda x: x in subnet_dest)
            else:
                mask_flow = self._flows["DST_IP"].apply(lambda x: x in subnet_dest)
                mask_ref = self._ref["DST_IP"].apply(lambda x: x in subnet_dest)

        return (
            self._flows[mask_flow].reset_index(drop=True),
            self._ref[mask_ref].reset_index(drop=True),
            mask_flow,
        )

    def _filter_time_segment(
        self, segment: SMTimeSegment
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series]:
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
            mask_flow = self._flows["START_TIME"].apply(
                lambda x: x >= start_time
            ) & self._flows["END_TIME"].apply(lambda x: x <= end_time)
            mask_ref = self._ref["START_TIME"].apply(
                lambda x: x >= start_time
            ) & self._ref["END_TIME"].apply(lambda x: x <= end_time)
        elif start_time is not None:
            mask_flow = self._flows["START_TIME"].apply(lambda x: x >= start_time)
            mask_ref = self._ref["START_TIME"].apply(lambda x: x >= start_time)
        else:
            mask_flow = self._flows["END_TIME"].apply(lambda x: x <= end_time)
            mask_ref = self._ref["END_TIME"].apply(lambda x: x <= end_time)

        return (
            self._flows[mask_flow].reset_index(drop=True),
            self._ref[mask_ref].reset_index(drop=True),
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
            "active flows",
            sim,
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        # "ct_flow_rate": ContinuousCounter(
        #    "flow rate",
        #    sim,
        #    measure_start_time=start_time_offset,
        #    measure_end_time=end_time_offset,
        # ),
        "ct_cpu_usage": ContinuousCounter(
            "CPU usage in percent",
            sim,
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "ct_ram_usage": ContinuousCounter(
            "RAM Usage in percent",
            sim,
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
            "active flows",
            sim,
            start_time,
            end_time,
            measure_start_time=start_time_offset,
            measure_end_time=end_time_offset,
        ),
        "tsc_flow_rate": TimeSeriesCounter(
            "flow rate",
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
            "RAM Usage in percent",
            sim,
            start_time,
            end_time,
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
    }

    metric_mapping: dict[str, List[str]] = {
        "data_rate": ["ct_data_rate", "ct_data_rate_bibit", "tsc_data_rate"],
        "packet_rate": ["ct_packet_rate", "tsc_packet_rate"],
        "flow_count": ["ct_flow_count", "tsc_flow_count"],
        "flow_rate": ["ct_flow_rate", "tsc_flow_rate"],
        "percent_CPU": ["ct_cpu_usage", "tsc_cpu_usage"],
        "percent_MEM": ["ct_ram_usage", "tsc_mem_usage"],
        "export_rate_f": ["ct_export_rate_f", "tsc_export_rate_f"],
        "export_rate_p": ["ct_export_rate_p", "tsc_export_rate_p"],
        "export_flows_p_packet": [
            "tsc_flows_per_export_packet",
            "ct_flows_per_export_packet",
        ],
    }

    return (statistic_objects, metric_mapping)


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
    current_data_rate = 0.0
    current_packet_rate = 0.0
    current_flow_count = np.uint64(0)
    current_flow_rate = 0.0

    # Prime the iterator
    event_iter = iter(event_queue)
    try:
        current_event = next(event_iter)
    except StopIteration:
        return  # No events to process

    last_time: np.uint64 = sim.get_time()
    last_export: np.uint64 = sim.get_time()
    sim.set_time(current_event.time)

    simultaneous_events = [current_event]

    for event in event_iter:
        if event.time == sim.get_time():
            simultaneous_events.append(event)
            continue

        # Compute the duration between the last time and the current group of events
        duration_ms = sim.get_time_diff(last_time)
        duration_s = sim.convert_to_seconds(duration_ms)
        since_last_export: np.uint64 = sim.get_time_diff(last_export)

        # Only advance stats if time progressed
        if (
            duration_ms > 0
            and not all_instance_of(simultaneous_events, OnePacketFlow)
            or duration_ms > 100
        ):
            # aggregate OnePacketFlow events within this window
            total_bytes = sum(e.bytes for e in one_packet_events)
            total_packets = sum(e.packets for e in one_packet_events)
            total_flows = np.uint64(sum(e.flows for e in one_packet_events))

            singleton_data_rate = (
                (total_bytes * 8) / duration_s if duration_s > 0 else 0.0
            )
            singleton_packet_rate = (
                total_packets / duration_s if duration_s > 0 else 0.0
            )

            singleton_flow_rate = total_flows / duration_s if duration_s > 0 else 0.0

            # Compose final rates
            total_data_rate = current_data_rate + singleton_data_rate
            total_packet_rate = current_packet_rate + singleton_packet_rate
            total_flow_count = current_flow_count + total_flows
            total_flow_rate = current_flow_rate + singleton_flow_rate

            update_statistic_objects(
                statistic_objects,
                metric_mapping,
                data_rate=total_data_rate,
                packet_rate=total_packet_rate,
                flow_count=total_flow_count,
                flow_rate=total_flow_rate,
            )

            export_events: List[ExportEvent] = [
                e for e in simultaneous_events if isinstance(e, ExportEvent)
            ]
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
                update_statistic_objects(
                    statistic_objects,
                    metric_mapping,
                    export_rate_f=0.0,
                    export_rate_b=0.0,
                    export_rate_p=0.0,
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

            # reset one-packet events after processing
            one_packet_events.clear()
            # move forward in time
            last_time = sim.get_time()

        # apply each event's effect to current rates
        for e in simultaneous_events:
            if isinstance(e, HostStatsEvent) or isinstance(e, ExportEvent):
                pass
            elif isinstance(e, OnePacketFlow):
                one_packet_events.append(e)
            else:
                current_data_rate += e.data_rate
                current_packet_rate += e.packet_rate
                current_flow_rate += e.flow_rate
                current_flow_count += e.flows

        sim.set_time(event.time)
        simultaneous_events = [event]

    # Final flush
    duration_ms = sim.get_time_diff(last_time)
    duration_s = sim.convert_to_seconds(duration_ms)

    if duration_s > 0:
        # aggregate OnePacketFlow events within this window
        total_bytes = sum(e.bytes for e in one_packet_events)
        total_packets = sum(e.packets for e in one_packet_events)
        total_flows = np.uint64(sum(e.flows for e in one_packet_events))

        singleton_data_rate = (total_bytes * 8) / duration_s if duration_s > 0 else 0.0
        singleton_packet_rate = total_packets / duration_s if duration_s > 0 else 0.0

        singleton_flow_rate = total_flows / duration_s if duration_s > 0 else 0.0

        # Compose final rates
        total_data_rate = current_data_rate + singleton_data_rate
        total_packet_rate = current_packet_rate + singleton_packet_rate
        total_flow_count = current_flow_count + total_flows
        total_flow_rate = current_flow_rate + singleton_flow_rate

        update_statistic_objects(
            statistic_objects,
            metric_mapping,
            data_rate=total_data_rate,
            packet_rate=total_packet_rate,
            flow_count=total_flow_count,
            flow_rate=total_flow_rate,
        )

        host_stats_event: HostStatsEvent = next(
            (e for e in simultaneous_events if isinstance(e, HostStatsEvent)),
            None,
        )
        if host_stats_event:
            update_statistic_objects(
                statistic_objects, metric_mapping, **host_stats_event.row._asdict()
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
