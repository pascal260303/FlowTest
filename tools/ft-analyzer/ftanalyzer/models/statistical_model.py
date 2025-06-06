"""
Author(s): Tomas Jansky <Tomas.Jansky@progress.com>

Copyright: (C) 2023 Flowmon Networks a.s.
SPDX-License-Identifier: BSD-3-Clause

"""

import ipaddress
import logging
import operator
import time
from functools import reduce
from typing import List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from ftanalyzer.common.pandas_multiprocessing import PandasMultiprocessingHelper
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
    }

    AGGREGATE_FLOWS = {
        "START_TIME": "min",
        "END_TIME": "max",
        "PACKETS": "sum",
        "BYTES": "sum",
    }

    def __init__(
        self,
        flows: str,
        reference: Union[str, pd.DataFrame],
        stats: GeneratorStats,
        merge: bool = False,
        biflows_ts_correction: bool = False,
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

        try:
            logging.getLogger().debug("reading file with flows=%s", flows)
            # ports could be empty in flows with protocol like ICMP
            flows = pd.read_csv(flows, engine="pyarrow", dtype=self.CSV_COLUMN_TYPES)
            flows["SRC_PORT"] = flows["SRC_PORT"].fillna(0)
            flows["DST_PORT"] = flows["DST_PORT"].fillna(0)
            self._flows: pd.DataFrame = flows.astype(self.CSV_COLUMN_TYPES)

            if isinstance(reference, str):
                logging.getLogger().debug("reading file with references=%s", reference)
                self._ref = pd.read_csv(reference, engine="pyarrow", dtype=self.CSV_COLUMN_TYPES)
            else:
                self._ref = reference
        except Exception as err:
            raise SMException("Unable to read file with flows.") from err

        if stats.start_time > 0:
            self._ref["START_TIME"] = self._ref["START_TIME"] + stats.start_time
            self._ref["END_TIME"] = self._ref["END_TIME"] + stats.start_time
            
            # filter out flows that start before the start time
            self._flows = self._flows[self._flows["START_TIME"] >= stats.start_time]
            
        #if stats.end_time > 0:
        #    # filter out flows that start before the end time
        #    self._flows = self._flows[self._flows["START_TIME"] <= stats.end_time]
            
        self._filter_multicast()

        if merge:
            self._merge_flows(biflows_ts_correction)
            
        self._generator_stats: GeneratorStats = stats
        self._flows_ip_addresses_converted = False
        self._ref_ip_addresses_converted = isinstance(reference, pd.DataFrame)

    def validate(self, rules: List[SMRule], check_complement: bool = False) -> StatisticalReport:
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

        report = StatisticalReport()
        all_flow_masks = []
        for rule in rules:
            flows, ref, mask_flow = self._filter_segment(rule.segment)
            all_flow_masks.append(mask_flow)

            # Check duplicated metrics.
            if len({m.key for m in rule.metrics}) != len(rule.metrics):
                raise SMException(f"Rule contains duplicated metrics: {rule.metrics}")

            duration = (flows["END_TIME"].max() - flows["START_TIME"].min()+1) / 1000
            ref_duration = (self._generator_stats.end_time - self._generator_stats.start_time +1) / 1000
            
            for metric in rule.metrics:
                match metric.key:
                    case SMMetricType.FLOWS:
                        value = len(flows.index)
                        reference = len(ref.index)
                    case SMMetricType.MBPS:
                        value = flows[SMMetricType.BYTES.value].sum() / duration / pow(10, 6)
                        reference = self._generator_stats.bytes / ref_duration / pow(10, 6)
                    case SMMetricType.PPS:
                        value = flows[SMMetricType.PACKETS.value].sum() / duration
                        reference = self._generator_stats.packets / ref_duration
                    case SMMetricType.DURATION:
                        value = duration
                        reference = ref_duration
                    case _:
                        value = flows[metric.key.value].sum()
                        reference = ref[metric.key.value].sum()                    

                report.add_test(
                    SMTestOutcome(
                        metric, rule.segment, value, reference, abs(np.int64(value) - np.int64(reference)) / reference
                    )
                )

        if check_complement:
            # pylint: disable=invalid-unary-operand-type
            flows = self._flows[~(reduce(operator.or_, all_flow_masks))].reset_index(drop=True)

            for metric in [SMMetric(SMMetricType.PACKETS, 0), SMMetric(SMMetricType.BYTES, 0)]:
                value = flows[metric.key.value].sum()
                reference = 0

                report.add_test(
                    SMTestOutcome(metric, "COMPLEMENT OF SEGMENTS", value, reference, 0 if value == reference else 1)
                )

        return report
    
    def _filter_multicast(self):
        # ipv4
        self._flows = self._flows[self._flows["DST_IP"] != "255.255.255.255"]
        
        #ipv6
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

        assert len(self._ref.index) == self._ref.groupby(self.FLOW_KEY).ngroups, "Cannot merge flows, duplicated key."

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
            flows["INV_SRC_PORT"] = np.where(swap_cond, flows["DST_PORT"], flows["SRC_PORT"])
            flows["INV_DST_PORT"] = np.where(swap_cond, flows["SRC_PORT"], flows["DST_PORT"])

            grouped = flows.groupby(self.DIR_INVARIANT_FLOW_KEY)
            flows["START_TIME"] = grouped["START_TIME"].transform("min")
            flows["END_TIME"] = grouped["END_TIME"].transform("max")

            self._flows = flows.loc[:, list(self.CSV_COLUMN_TYPES.keys()) + ["FLOW_COUNT"]]

    def _convert_ip_addresses(self) -> None:
        """Convert str ip addresses to objects (ipaddress library) in DataFrames."""

        if self._flows_ip_addresses_converted and self._ref_ip_addresses_converted:
            return

        logging.getLogger().debug("Start applying ip_address...")
        start = time.time()
        with PandasMultiprocessingHelper() as pool:
            pool.apply(self._flows, [("SRC_IP", ipaddress.ip_address, []), ("DST_IP", ipaddress.ip_address, [])])
            if not self._ref_ip_addresses_converted:
                # convert to object only when reference is loaded from CSV file
                pool.apply(self._ref, [("SRC_IP", ipaddress.ip_address, []), ("DST_IP", ipaddress.ip_address, [])])
        end = time.time()
        logging.getLogger().debug("IP address applied in %.2f seconds.", (end - start))

        self._flows_ip_addresses_converted, self._ref_ip_addresses_converted = (True, True)

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

    def _filter_subnet_segment(self, segment: SMSubnetSegment) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series]:
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

        subnet_source = ipaddress.ip_network(segment.source) if segment.source is not None else None
        subnet_dest = ipaddress.ip_network(segment.dest) if segment.dest is not None else None

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
                mask_flow = self._flows["SRC_IP"].apply(lambda x: x in subnet_source) & self._flows["DST_IP"].apply(
                    lambda x: x in subnet_dest
                )
                mask_ref = self._ref["SRC_IP"].apply(lambda x: x in subnet_source) & self._ref["DST_IP"].apply(
                    lambda x: x in subnet_dest
                )
        elif subnet_source is not None:
            if segment.bidir:
                mask_flow = self._flows["SRC_IP"].apply(lambda x: x in subnet_source) | self._flows["DST_IP"].apply(
                    lambda x: x in subnet_source
                )
                mask_ref = self._ref["SRC_IP"].apply(lambda x: x in subnet_source) | self._ref["DST_IP"].apply(
                    lambda x: x in subnet_source
                )
            else:
                mask_flow = self._flows["SRC_IP"].apply(lambda x: x in subnet_source)
                mask_ref = self._ref["SRC_IP"].apply(lambda x: x in subnet_source)
        else:
            if segment.bidir:
                mask_flow = self._flows["SRC_IP"].apply(lambda x: x in subnet_dest) | self._flows["DST_IP"].apply(
                    lambda x: x in subnet_dest
                )
                mask_ref = self._ref["SRC_IP"].apply(lambda x: x in subnet_dest) | self._ref["DST_IP"].apply(
                    lambda x: x in subnet_dest
                )
            else:
                mask_flow = self._flows["DST_IP"].apply(lambda x: x in subnet_dest)
                mask_ref = self._ref["DST_IP"].apply(lambda x: x in subnet_dest)

        return (
            self._flows[mask_flow].reset_index(drop=True),
            self._ref[mask_ref].reset_index(drop=True),
            mask_flow,
        )

    def _filter_time_segment(self, segment: SMTimeSegment) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series]:
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
            mask_flow = self._flows["START_TIME"].apply(lambda x: x >= start_time) & self._flows["END_TIME"].apply(
                lambda x: x <= end_time
            )
            mask_ref = self._ref["START_TIME"].apply(lambda x: x >= start_time) & self._ref["END_TIME"].apply(
                lambda x: x <= end_time
            )
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
