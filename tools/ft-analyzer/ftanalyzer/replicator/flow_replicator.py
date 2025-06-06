"""
Author(s): Jan Sobol <sobol@cesnet.cz>

Copyright: (C) 2023 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

FlowReplicator tool. Tool is used to replicate flows in reference CSV file, which is necessary
in case a replicator (ft-replay) was used as a generator during testing.
"""

from __future__ import annotations

import ipaddress
import logging
import operator
import re
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, Union

import numpy as np
import pandas as pd
from ftanalyzer.common.pandas_multiprocessing import PandasMultiprocessingHelper


class FlowReplicatorException(Exception):
    """General exception used in flow replicator."""


@dataclass
class IpAddConstant:
    """Ip address modifier. Result of parsing of addConstant(number) or addOffset(number).

    Attributes
    ----------
    value : int
        Parameter of modifier function. Constant value.
    """

    value: int


@dataclass
class ReplicatorUnit:
    """Representation of single replication unit. Source IP or destination IP can be changed with modifier.

    Attributes
    ----------
    srcip : IpAddConstant, optional
        Source IP modifier. If None, no changes during replication.
    dstip : IpAddConstant, optional
        Destination IP modifier. If None, no changes during replication.
    loop_only : Iterable or None, optional
        Apply replication unit only in loops that match given index(es).
    """

    srcip: Optional[IpAddConstant]
    dstip: Optional[IpAddConstant]
    loop_only: Optional[Iterable] = None


@dataclass
class ReplicatorConfig:
    """Representation of replicator configuration. Parsed from dict (ft-replay like) representation.

    Attributes
    ----------
    units : list
        List of replication units.
        In each loop, all replication units take the source flows and replicate (copy and edit) them.
    loop : list
        Defines behavior of IP addresses modifying in loops. An IP offset can be set to provide IP subnet separation.
    """

    units: List[ReplicatorUnit]
    loop: ReplicatorUnit


# pylint: disable=too-few-public-methods
class FlowReplicator:
    """FlowReplicator tool. Tool is used to replicate flows in reference CSV file, which is necessary in case
    a replicator (ft-replay) was used as a generator during testing.

    Data source must be CSV files with the following columns (order of columns does not matter):
        START_TIME: time of the first observed packet in the flow (UTC timestamp in milliseconds)
        END_TIME: time of the last observed packet in the flow (UTC timestamp in milliseconds)
        PROTOCOL: protocol number defined by IANA
        SRC_IP: source IP address (IPv4 or IPv6)
        DST_IP: destination IP address (IPv4 or IPv6)
        SRC_PORT: source port number (can be 0 if the flow does not contain TCP or UDP protocol)
        DST_PORT: destination port number (can be 0 if the flow does not contain TCP or UDP protocol)
        PACKETS: number of transferred packets
        BYTES: number of transferred bytes (IP headers + payload)

    Replicator automatically merges flows that have the same flow key within single replay loop. This behavior occurs
    when multiple replication units do not affect the source or destination ip address.

    Replicator is able to merge flows with the same flow key across replay loops. This feature must be enabled with
    parameter 'merge_across_loops'. Merging takes into account inactive timeout: when gap between end and start of two
    flows with the same flow key is greater or equal than inactive timeout, flows are left unmerged as well as in export
    from a probe.

    "addConstant(number)" and "addOffset(number)" IP modifiers are supported. "addCounter" ft-replay modifier is
    unsupported because of nondeterministic IP address distribution to replication workers/threads.

    Attributes
    ----------
    _config : ReplicatorConfig
        Replicator configuration - ft-replay style.
    _flows : pd.DataFrame
        Source (original) flow records.
    _inactive_timeout : int or None
        Probe inactive timeout in milliseconds. Used when merging across loops.
    """

    FLOW_KEY = ["PROTOCOL", "SRC_IP", "DST_IP", "SRC_PORT", "DST_PORT"]
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
    AGGREGATE_SPLIT_FLOWS = {
        "START_TIME": "min",
        "END_TIME": "max",
        "PACKETS": "sum",
        "BYTES": "sum",
    }

    class IPv6Address(ipaddress.IPv6Address):
        """Custom representation of IPv6 address which edits only first 4 bytes when adding a number.
        __lt__ can be performed over addresses with different versions (4 or 6).
        Necessary for DataFrame grouping.
        """

        def __add__(self, other: int) -> FlowReplicator.IPv6Address:
            if not isinstance(other, int):
                return NotImplemented
            added = int(self) + 2**96 * other
            # overflow address
            while added >= 2**128:
                added -= 2**128
            return self.__class__(added)

        def __lt__(self, other):
            if self._ip != other._ip:
                return self._ip < other._ip
            return False

    class IPv4Address(ipaddress.IPv4Address):
        """Custom representation of IPv4 address.
        __lt__ can be performed over addresses with different versions (4 or 6).
        Necessary for DataFrame grouping.
        """

        def __add__(self, other: int) -> FlowReplicator.IPv4Address:
            if not isinstance(other, int):
                return NotImplemented
            added = int(self) + other
            # overflow address
            while added >= 2**32:
                added -= 2**32
            return self.__class__(added)

        def __lt__(self, other):
            if self._ip != other._ip:
                return self._ip < other._ip
            return False

    @staticmethod
    def ip_address(address: Any) -> Union[FlowReplicator.IPv6Address, FlowReplicator.IPv4Address]:
        """Custom IP address parser. Custom IPv6Adress or IPv4Address object is returned."""

        obj = ipaddress.ip_address(address)
        if isinstance(obj, ipaddress.IPv6Address):
            return FlowReplicator.IPv6Address(obj)
        return FlowReplicator.IPv4Address(obj)

    def __init__(self, config: dict, ignore_loops: Optional[list[int]] = None) -> None:
        """Init flow replicator. Parse config dict.

        Parameters
        ----------
        config : dict
            Configuration in form of dict, the same as ft-replay configuration.
        ignore_loops : list[int], optional
            Do not replicate flows in loops with indices.
            Replication units that are active only in these loops may contain unsupported modifiers (addCounter).

        Raises
        ------
        FlowReplicatorException
            When bad config format or unsupported replication modifier is used.
        """

        self._ignore_loops = [] if ignore_loops is None else ignore_loops
        self._config = self._normalize_config(config)
        self._flows = None
        self._inactive_timeout = None

    def replicate(
        self,
        input_file: str,
        loops: int,
        merge_across_loops: bool = False,
        inactive_timeout: int = -1,
        speed_multiplier: float = 1,
    ) -> pd.DataFrame:
        """Read source data and replicate source flows based on configuration.
        Save replication result to CSV file. Helper columns like "ORIG_INDEX" are not exported.

        Parameters
        ----------
        input_file : str
            Path to CSV file with source flow records.
        output_file : str
            Path to output CSV file to save replicated flows.
        loops : int
            Number of replay loops.
        merge_across_loops : bool, optional
            Set to true when flows are to be merged across loops.
            Feature description is provided in FlowReplicator docstring.
        inactive_timeout : int, optional
            Probe inactive timeout in seconds. Time after which inactive flow is marked as ended.
            Ignored during merge if the value is -1.
        speed_multiplier : float, optional
            Modify flows timestamps according to real number multiplier. The value
            corresponds to traffic replay speed. Value 1 means the original layout.
            Value 0.5 means that flows will take twice as long. 2.0 means that flows
            will take half the time.

        Raises
        ------
        FlowReplicatorException
            When source CSV file cannot be read.
        """

        try:
            self._flows = pd.read_csv(input_file, engine="pyarrow", dtype=self.CSV_COLUMN_TYPES)
        except Exception as err:
            raise FlowReplicatorException("Unable to read file with flows.") from err

        with PandasMultiprocessingHelper() as pool:
            pool.apply(self._flows, [("SRC_IP", self.ip_address, []), ("DST_IP", self.ip_address, [])])

            # index of source flow is used when merging flows within single loop
            self._flows["ORIG_INDEX"] = self._flows.index

            # transform speed to time multiplier
            # e.g. time multiplier 0.5 corresponds to traffic played 2x faster
            time_multiplier = 1 / speed_multiplier

            # replicate and drop original record indexes - deduplicate
            result = self._replicate(loops, time_multiplier)
            result.reset_index(drop=True, inplace=True)
            result.reindex()

            pool.binary(
                result,
                [
                    ("SRC_IP", operator.add, "SRC_IP", "_SRC_IP_OFFSET", []),
                    ("DST_IP", operator.add, "DST_IP", "_DST_IP_OFFSET", []),
                ],
            )

        if merge_across_loops:
            self._inactive_timeout = inactive_timeout * 1000 if inactive_timeout > -1 else None
            result = self._merge_across_loop(result)

        return result.loc[:, self.CSV_COLUMN_TYPES.keys()]

    @staticmethod
    def _parse_config_item(item: str, src_dict: dict) -> Optional[IpAddConstant]:
        """Parse single modifier in configuration. In replication unit section or loop section.

        Parameters
        ----------
        item : str
            Name of parsed item, e.g. "srcip" or "dstip".
        src_dict : dict
            Nested dict in which the item is parsed.

        Returns
        -------
        IpAddConstant or None
            Parsed modifier if found in src_dict. Otherwise None.

        Raises
        ------
        FlowReplicatorException
            When modifier function is not supported by flow replicator.
        """

        if item in src_dict and src_dict[item] != "None":
            func = src_dict[item]
        else:
            return None

        if func.startswith("addConstant"):
            return IpAddConstant(int(re.findall(r"\d+", func)[0]))
        if func.startswith("addOffset"):
            return IpAddConstant(int(re.findall(r"\d+", func)[0]))

        raise FlowReplicatorException(
            f"Value '{func}' in replicator configuration is not supported by flow replicator (ft-analyzer)."
        )

    def _normalize_config(self, config: dict) -> ReplicatorConfig:
        """Parse, check and get replicator configuration in ReplicatorConfig representation.

        Parameters
        ----------
        config : dict
            Dictionary with "units" and "loop" configuration (ft-replay style).

        Returns
        -------
        ReplicatorConfig
            Parsed replicator configuration.

        Raises
        ------
        FlowReplicatorException
            When configuration dict has bad format.
        """

        if not set(config.keys()).issubset({"units", "loop"}):
            raise FlowReplicatorException("Only 'units' and 'loop' keys are allowed in replicator configuration.")

        units = []
        for unit in config.get("units", []):
            loop_only = unit.get("loopOnly", [])
            if loop_only == "All":
                loop_only = {}
            elif isinstance(loop_only, int):
                loop_only = {loop_only}
            else:
                loop_only = set(loop_only)

            if len(loop_only) > 0 and loop_only.issubset(set(self._ignore_loops)):
                continue

            units.append(
                ReplicatorUnit(
                    self._parse_config_item("srcip", unit),
                    self._parse_config_item("dstip", unit),
                    loop_only,
                )
            )

        loop_config = config.get("loop", {})
        loop = ReplicatorUnit(
            self._parse_config_item("srcip", loop_config), self._parse_config_item("dstip", loop_config)
        )

        return ReplicatorConfig(units, loop)

    def _replicate(self, loops: int, time_multiplier: float) -> pd.DataFrame:
        """Replicate flows from source according to the configuration.

        Parameters
        ----------
        loops : int
            Number of replay loops.
        time_multiplier : float
            Time multiplier propagated from replicate method.

        Returns
        -------
        pd.DataFrame
            Replicated flows.
        """

        loop_start = int(self._flows.loc[:, "START_TIME"].min())
        loop_end = int(self._flows.loc[:, "END_TIME"].max())
        loop_length = int((loop_end - loop_start) * time_multiplier)

        self._flows["_FLOW_LEN"] = ((self._flows["END_TIME"] - self._flows["START_TIME"]) * time_multiplier).astype(
            np.uint64
        )
        self._flows["_START_OFFSET"] = ((self._flows["START_TIME"] - loop_start) * time_multiplier).astype(np.uint64)

        self._flows["_SRC_IP_OFFSET"] = 0
        self._flows["_DST_IP_OFFSET"] = 0

        tmp_dataframes = []
        for loop_n in range(loops):
            logging.getLogger().debug("Processing %d loop...", loop_n)
            if loop_n in self._ignore_loops:
                continue
            tmp_dataframes.append(self._process_single_loop(loop_n, loop_start, loop_length))

        res = pd.concat(tmp_dataframes, axis=0)
        return res

    def _process_single_loop(self, loop_n: int, global_start: int, loop_length: int) -> pd.DataFrame:
        """Replicate flows for single loop. Copy, add time offset to timestamps and replicate with units.

        Parameters
        ----------
        loop_n : int
            Sequence number of loop.
        global_start : int
            Timestamp of first loop start.
        loop_length : int
            Duration of one loop in milliseconds.

        Returns
        -------
        pd.DataFrame
            Replicated flows (deep copy).
        """

        time_offset = global_start + loop_n * loop_length
        srcip_offset = 0
        dstip_offset = 0
        if self._config.loop.srcip:
            srcip_offset += loop_n * self._config.loop.srcip.value
        if self._config.loop.dstip:
            dstip_offset += loop_n * self._config.loop.dstip.value

        flows = self._flows.copy()
        flows["START_TIME"] = time_offset + flows["_START_OFFSET"]
        flows["END_TIME"] = flows["START_TIME"] + flows["_FLOW_LEN"]

        flows["_SRC_IP_OFFSET"] = flows["_SRC_IP_OFFSET"] + srcip_offset
        flows["_DST_IP_OFFSET"] = flows["_DST_IP_OFFSET"] + dstip_offset

        res = [
            self._process_replication_unit(unit, flows)
            for unit in self._config.units
            if len(unit.loop_only) == 0 or loop_n in unit.loop_only
        ]
        res = pd.concat(res, axis=0)

        # merge replicated flows with the same key within one loop
        # (when replication unit does not change src nor dst ip)
        # ORIG_INDEX - leave flows that are separated in input csv unmerged - expectation of correct reference
        # (e.g. two flows with the same flow key at different times)
        key = self.FLOW_KEY + ["ORIG_INDEX", "_SRC_IP_OFFSET", "_DST_IP_OFFSET"]
        res = res.groupby(key, sort=False)
        res = res.agg(self.AGGREGATE_SPLIT_FLOWS).reset_index()
        res.reindex()
        res.sort_values(by=["ORIG_INDEX"], inplace=True)

        return res

    def _process_replication_unit(self, unit: ReplicatorUnit, orig_flows: pd.DataFrame) -> pd.DataFrame:
        """Replicate flows by single replication unit within single loop.

        Parameters
        ----------
        unit : ReplicatorUnit
            Configuration of replication unit.
        orig_flows : pd.DataFrame
            Source flows with corrected timestamps and IP addresses according to the loop being processed.

        Returns
        -------
        pd.DataFrame
            Replicated flows (deep copy).
        """

        flows = orig_flows.copy()
        if unit.srcip:
            flows["_SRC_IP_OFFSET"] = flows["_SRC_IP_OFFSET"] + unit.srcip.value
        if unit.dstip:
            flows["_DST_IP_OFFSET"] = flows["_DST_IP_OFFSET"] + unit.dstip.value
        return flows

    def _merge_func(self, group: pd.DataFrame) -> pd.DataFrame:
        """Helper function used on group to merge flows across loops.

        Parameters
        ----------
        group : pd.DataFrame
            Grouped flows by flow key.

        Returns
        -------
        pd.DataFrame
            Merged flows.
        """

        # check if group has more than 1 flow (row)
        if group.shape[0] > 1:
            # drop original index, index within a group from 0
            group.reset_index(drop=True, inplace=True)
            group.reindex()

            # create column with start time of following flow (shift by 1)
            next_start = group["START_TIME"][1:]
            next_start.reset_index(drop=True, inplace=True)
            next_start.reindex()

            group["GAP"] = next_start - group["END_TIME"]
            group["AGGR_NO"] = 0

            if self._inactive_timeout:
                # split merge group when gap between flows are greater or equal inactive timeout
                aggr_no = 0
                for index, row in group.iterrows():
                    group.at[index, "AGGR_NO"] = aggr_no
                    if row["GAP"] >= self._inactive_timeout:
                        aggr_no += 1

            res_group = group.groupby(self.FLOW_KEY + ["AGGR_NO"]).aggregate(self.AGGREGATE_SPLIT_FLOWS).reset_index()
            res_group.reindex()
            return res_group
        return group

    def _merge_across_loop(self, flows: pd.DataFrame) -> pd.DataFrame:
        """Merge replicated flows across loops.
        Feature description is provided in FlowReplicator docstring.

        Warning: merging does not take ORIG_INDEX into account, so if the source contains multiple flow records with
        the same flow key, the records will be merged.

        Parameters
        ----------
        flows : pd.DataFrame
            Replicated flows to be merged.

        Returns
        -------
        pd.DataFrame
            Merged flows.
        """

        return flows.groupby(self.FLOW_KEY).apply(self._merge_func)
