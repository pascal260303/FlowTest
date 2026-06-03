"""
Author(s): Jan Sobol <sobol@cesnet.cz>

Copyright: (C) 2023 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

FlowReplicator tool. Tool is used to replicate flows in reference CSV file, which is necessary
in case a replicator (ft-replay) was used as a generator during testing.
"""

from __future__ import annotations

import atexit
import ipaddress
import logging
import operator
import os
from pathlib import Path
import re
from dataclasses import dataclass
import tempfile
import time
from typing import Any, Iterable, List, Optional, Union
from lbr_testsuite.executable import Tool

import numpy as np
import pandas as pd
import psutil
import shutil
from ftanalyzer.common.pandas_multiprocessing import PandasMultiprocessingHelper
from src.generator.interface import GeneratorStats

_TEMP_FILES = []


def _cleanup_temp_files():
    for path in _TEMP_FILES:
        try:
            Path(path).unlink()
        except FileNotFoundError:
            pass


# Register only once
atexit.register(_cleanup_temp_files)


class FlowReplicatorException(Exception):
    """General exception for flow replicator errors."""


@dataclass
class IpAddConstant:
    """
    IP address modifier. Result of parsing addConstant(number) or addOffset(number).

    Attributes:
        value (int): Constant value for the modifier function.
    """

    value: int


@dataclass
class ReplicatorUnit:
    """
    Representation of a single replication unit. Source or destination IP can be changed with a modifier.

    Attributes:
        srcip (IpAddConstant, optional): Source IP modifier. If None, no changes during replication.
        dstip (IpAddConstant, optional): Destination IP modifier. If None, no changes during replication.
        loop_only (Iterable or None, optional): Apply replication unit only in loops matching given indices.
    """

    srcip: Optional[IpAddConstant]
    dstip: Optional[IpAddConstant]
    loop_only: Optional[Iterable] = None


@dataclass
class ReplicatorConfig:
    """
    Representation of replicator configuration. Parsed from dict (ft-replay style).

    Attributes:
        units (list): List of replication units. In each loop, all units replicate (copy and edit) the source flows.
        loop (ReplicatorUnit): Defines IP address modification behavior in loops. An IP offset can provide subnet separation.
    """

    units: List[ReplicatorUnit]
    loop: ReplicatorUnit


# pylint: disable=too-few-public-methods
class FlowReplicator:
    """
    FlowReplicator tool. Used to replicate flows in a reference CSV file, necessary when a replicator (ft-replay) was used as a generator during testing.

    Data source must be CSV files with the following columns (order does not matter):
        START_TIME: time of the first observed packet in the flow (UTC timestamp in milliseconds)
        END_TIME: time of the last observed packet in the flow (UTC timestamp in milliseconds)
        PROTOCOL: protocol number defined by IANA
        SRC_IP: source IP address (IPv4 or IPv6)
        DST_IP: destination IP address (IPv4 or IPv6)
        SRC_PORT: source port number (can be 0 if the flow does not contain TCP or UDP)
        DST_PORT: destination port number (can be 0 if the flow does not contain TCP or UDP)
        PACKETS: number of transferred packets
        BYTES: number of transferred bytes (IP headers + payload)

    Replicator automatically merges flows with the same flow key within a single replay loop. This occurs when multiple replication units do not affect the source or destination IP address.

    Replicator can merge flows with the same flow key across replay loops (enabled with 'merge_across_loops'). Merging considers inactive timeout: if the gap between end and start of two flows with the same key is greater or equal to inactive timeout, flows are left unmerged as in probe export.

    Supported IP modifiers: "addConstant(number)", "addOffset(number)". "addCounter" is unsupported due to nondeterministic IP address distribution to replication workers/threads.

    Attributes:
        _config (ReplicatorConfig): Replicator configuration (ft-replay style).
        _flows (pd.DataFrame): Source (original) flow records.
        _inactive_timeout (int or None): Probe inactive timeout in milliseconds, used when merging across loops.
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
    def ip_address(
        address: Any,
    ) -> Union[FlowReplicator.IPv6Address, FlowReplicator.IPv4Address]:
        """Custom IP address parser. Custom IPv6Adress or IPv4Address object is returned."""

        obj = ipaddress.ip_address(address)
        if isinstance(obj, ipaddress.IPv6Address):
            return FlowReplicator.IPv6Address(obj)
        return FlowReplicator.IPv4Address(obj)

    def __init__(self, config: dict, ignore_loops: Optional[List[int]] = None) -> None:
        """Init flow replicator. Parse config dict.

        Parameters
        ----------
        config : dict
            Configuration in form of dict, the same as ft-replay configuration.
        ignore_loops : List[int], optional
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
        generator_stats: GeneratorStats,
        output_file: str = None,
        merge_across_loops: bool = False,
        inactive_timeout: int = -1,
        speed_multiplier: float = 1,
        chunksize: int = 5_000_000,
    ) -> tuple[pd.DataFrame | os.PathLike, float]:
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
        start = time.time()

        if not output_file:
            output_file = tempfile.NamedTemporaryFile(
                delete=False, suffix=".csv", prefix="tmp_ref_"
            ).name
            _TEMP_FILES.append(output_file)

        if output_file.startswith("tmp_ref_"):
            _TEMP_FILES.append(output_file)

        # First pass: compute min and max timestamps
        loop_start, loop_end = None, None
        try:
            for chunk in pd.read_csv(
                input_file,
                usecols=["START_TIME", "END_TIME"],
                dtype={
                    "START_TIME": np.uint64,
                    "END_TIME": np.uint64,
                },
                chunksize=chunksize,
            ):
                start_min = chunk["START_TIME"].min()
                end_max = chunk["END_TIME"].max()
                loop_start = (
                    start_min if loop_start is None else min(loop_start, start_min)
                )
                loop_end = end_max if loop_end is None else max(loop_end, end_max)
        except Exception as err:
            raise FlowReplicatorException("Unable to read file with flows.") from err

        if loop_start is None or loop_end is None:
            raise FlowReplicatorException("Input file appears empty or corrupt.")

        loop_start = int(loop_start)
        loop_end = int(loop_end)

        if speed_multiplier == 1:
            # derive speed multiplier from actual replay times (not really correct)
            speed_multiplier = (
                (loop_end - loop_start)
                * loops
                / (generator_stats.end_time - generator_stats.start_time)
            )

        time_multiplier = 1 / speed_multiplier
        loop_length = int((loop_end - loop_start) * time_multiplier)

        first_write = True

        # adapt chunksize to available memory to avoid swapping
        try:
            recommended = self._recommend_chunksize()
            if chunksize is None:
                chunksize = recommended
            elif chunksize > recommended:
                logging.getLogger().warning(
                    "Provided chunksize %d is large for available memory, reducing to %d",
                    chunksize,
                    recommended,
                )
                chunksize = recommended
        except Exception:
            # fallback to provided chunksize on any error
            pass

        with PandasMultiprocessingHelper() as pool:
            for chunk in pd.read_csv(
                input_file, dtype=self.CSV_COLUMN_TYPES, chunksize=chunksize
            ):
                pool.apply(
                    chunk,
                    [("SRC_IP", self.ip_address, []), ("DST_IP", self.ip_address, [])],
                )
                chunk["ORIG_INDEX"] = chunk.index

                self._replicate(
                    chunk=chunk,
                    loops=loops,
                    loop_start=loop_start,
                    loop_length=loop_length,
                    time_multiplier=time_multiplier,
                    output_file=output_file,
                    first_write=first_write,
                    real_start=generator_stats.start_time,
                )
                first_write = False

            if merge_across_loops:
                self._inactive_timeout = (
                    inactive_timeout * 1000 if inactive_timeout > -1 else None
                )
                self._merge_across_loop(output_file)

        end = time.time()
        logging.getLogger().info("CSV replicated in %.2f seconds.", (end - start))
        return (output_file, speed_multiplier)

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
            raise FlowReplicatorException(
                "Only 'units' and 'loop' keys are allowed in replicator configuration."
            )

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
            self._parse_config_item("srcip", loop_config),
            self._parse_config_item("dstip", loop_config),
        )

        return ReplicatorConfig(units, loop)

    def _replicate(
        self,
        chunk: pd.DataFrame,
        loops: int,
        loop_start: int,
        loop_length: int,
        real_start: int,
        time_multiplier: float,
        output_file: str,
        first_write: bool,
    ):
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

        chunk["_FLOW_LEN"] = (
            (chunk["END_TIME"] - chunk["START_TIME"]) * time_multiplier
        ).astype(np.uint64)

        chunk["_START_OFFSET"] = (
            (chunk["START_TIME"] - loop_start) * time_multiplier + real_start
        ).astype(np.uint64)

        chunk["_SRC_IP_OFFSET"] = 0
        chunk["_DST_IP_OFFSET"] = 0

        for loop_n in range(loops):
            logging.getLogger().debug("Processing loop %d...", loop_n)
            if loop_n in self._ignore_loops:
                continue

            self._flows = chunk  # used internally by _process_single_loop
            replicated = self._process_single_loop(loop_n, loop_start, loop_length)
            with PandasMultiprocessingHelper() as binary_pool:
                binary_pool.binary(
                    replicated,
                    [
                        ("SRC_IP", operator.add, "SRC_IP", "_SRC_IP_OFFSET", []),
                        ("DST_IP", operator.add, "DST_IP", "_DST_IP_OFFSET", []),
                    ],
                )
            replicated[self.CSV_COLUMN_TYPES.keys()].to_csv(
                output_file,
                index=False,
                mode="w" if first_write else "a",
                header=first_write,
            )
            first_write = False

    def _process_single_loop(
        self, loop_n: int, global_start: int, loop_length: int
    ) -> pd.DataFrame:
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

        flows = self._flows.copy(deep=False)
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

    def _process_replication_unit(
        self, unit: ReplicatorUnit, orig_flows: pd.DataFrame
    ) -> pd.DataFrame:
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
            # vectorized: GAP = START_TIME of next row - END_TIME of current row
            group["GAP"] = group["START_TIME"].shift(-1) - group["END_TIME"]

            # AGGR_NO is the number of splits that occurred before the given row
            # a split occurs when GAP >= inactive_timeout. We compute a boolean series
            # of split points, take its cumulative sum and shift it by 1 so that the
            # AGGR_NO for the current row equals the number of splits in previous rows.
            if self._inactive_timeout:
                splits = (
                    (group["GAP"] >= self._inactive_timeout).fillna(False).astype(int)
                )
                group["AGGR_NO"] = splits.cumsum().shift(1, fill_value=0).astype(int)
            else:
                group["AGGR_NO"] = 0

            res_group = (
                group.groupby(self.FLOW_KEY + ["AGGR_NO"])
                .aggregate(self.AGGREGATE_SPLIT_FLOWS)
                .reset_index()
            )
            res_group.reindex()
            return res_group
        return group

    def _merge_across_loop(self, flows_file: os.PathLike) -> pd.DataFrame:
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
        # memory-aware partitioned merge to avoid peak RAM growth
        available = psutil.virtual_memory().available
        estimated = self._estimate_memory_from_file(flows_file, self.CSV_COLUMN_TYPES)
        if available < estimated + 1024**3:
            logging.getLogger().info(
                "Available RAM low, using partitioned merge to reduce peak memory usage"
            )

            # number of partitions chosen heuristically based on size
            partitions = max(2, min(32, int(estimated // (200 * 1024**2)) + 1))

            tmp_dir = tempfile.mkdtemp(prefix="merge_parts_")
            _TEMP_FILES.append(tmp_dir)

            part_files = [
                tempfile.NamedTemporaryFile(
                    mode="w", delete=False, dir=tmp_dir, suffix=".csv"
                )
                for _ in range(partitions)
            ]

            # write headers
            header = ",".join(self.CSV_COLUMN_TYPES.keys()) + "\n"
            for f in part_files:
                f.write(header)
                f.flush()

            # partition rows by hash of FLOW_KEY
            for chunk in pd.read_csv(
                flows_file, dtype=self.CSV_COLUMN_TYPES, chunksize=100_000
            ):
                # compute partition index
                keys = chunk[self.FLOW_KEY].astype(str).agg("|".join, axis=1)
                idx = (keys.apply(hash).abs() % partitions).to_numpy()
                for i in range(partitions):
                    sel = idx == i
                    if sel.any():
                        chunk.loc[sel, list(self.CSV_COLUMN_TYPES.keys())].to_csv(
                            part_files[i].name, mode="a", index=False, header=False
                        )

            for f in part_files:
                f.close()

            # process each partition independently and append to final file
            out_tmp = tempfile.NamedTemporaryFile(
                mode="w", delete=False, dir=tmp_dir, suffix="_out.csv"
            )
            out_tmp.close()

            first = True
            for pf in [p.name for p in part_files]:
                df = pd.read_csv(pf, dtype=self.CSV_COLUMN_TYPES)
                if df.empty:
                    continue
                df = df.groupby(self.FLOW_KEY, sort=False).apply(self._merge_func)
                df.to_csv(
                    out_tmp.name, mode="w" if first else "a", index=False, header=first
                )
                first = False

            # replace original file
            shutil.move(out_tmp.name, flows_file)

            # cleanup partition files
            for p in part_files:
                try:
                    os.remove(p.name)
                except Exception:
                    pass
            try:
                shutil.rmtree(tmp_dir)
            except Exception:
                pass
            return

        # default path when enough memory: perform in-memory groupby.apply
        (
            pd.read_csv(
                flows_file,
                usecols=self.CSV_COLUMN_TYPES.keys(),
                dtype=self.CSV_COLUMN_TYPES,
                engine="pyarrow",
            )
            .groupby(self.FLOW_KEY)
            .apply(self._merge_func)
            .to_csv(flows_file, index=False)
        )

    def _recommend_chunksize(self) -> int:
        """Recommend chunksize based on available memory and approximate row size.

        Returns an integer number of rows to read per chunk.
        """
        available = psutil.virtual_memory().available
        # aim to use at most 1/8 of available memory for chunk data
        budget = max(10 * 1024**2, int(available // 8))
        # estimate bytes per row similar to _estimate_memory_from_file
        bytes_per_row = 0
        for t in self.CSV_COLUMN_TYPES.values():
            if hasattr(t, "itemsize"):
                bytes_per_row += int(np.dtype(t).itemsize)
            else:
                bytes_per_row += 60
        rows = max(1000, int(budget // max(1, bytes_per_row)))
        return rows

    def _estimate_memory_from_file(self, csv_path: str, column_types: dict):
        bytes_per_row = sum(
            np.dtype(t).itemsize
            for t in column_types.values()
            if hasattr(t, "itemsize")
        )
        bytes_per_row += sum(
            60 for s in column_types if isinstance(s, str)
        )  # assume average of 60 bytes per string
        rows, _ = Tool(f"wc -l {csv_path}").run()
        rows = int(rows.split(" ", 1)[0]) - 1

        estimated_memory_bytes = rows * bytes_per_row
        return estimated_memory_bytes
