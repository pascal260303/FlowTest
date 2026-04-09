from abc import ABC, abstractmethod
import atexit
import csv
import heapq
from io import TextIOWrapper
import math
import os
import random
import shutil
import tempfile
from typing import Any, Callable, Iterator
import numpy as np
import pandas as pd

CSV_COLUMN_TYPES = {
    "START_TIME": np.uint64,
    "END_TIME": np.uint64,
    # "PROTOCOL": np.uint8,
    # "SRC_IP": str,
    # "DST_IP": str,
    # "SRC_PORT": np.uint16,
    # "DST_PORT": np.uint16,
    "PACKETS": np.uint64,
    "BYTES": np.uint64,
    "EXPORT_TIME": np.uint64,
    "SEQ_NUMBER": np.uint32,
    "MSG_LENGTH": np.uint64,
}

CSV_AGGREGATE_TYPES = {
    "START_TIME": np.uint64,
    "END_TIME": np.uint64,
    "PACKETS": np.uint64,
    "BYTES": np.uint64,
    "FLOWS": np.uint64,
    "ACTIVE_TIME": np.uint64,
    "CACHE_TIME": np.uint64,
}

STATS_CSV_COLUMN_TYPES = {
    "Time": np.uint64,
    # "UID": np.uint64,
    # "PID": np.uint64,
    # "percent_usr": np.float64,
    # "percent_system": np.float64,
    # "percent_guest": np.float64,
    # "percent_wait": np.float64,
    "percent_CPU": np.float64,
    # "CPU": np.uint64,
    # "minflt/s": np.float64,
    # "majflt/s": np.float64,
    # "VSZ": np.uint64,
    # "RSS": np.uint64,
    # "percent_MEM": np.float64,
    # "StkSize": np.uint64,
    # "StkRef": np.uint64,
    # "threads": np.uint64,
    # "fd-nr": np.uint64,
    # "Command": str,
    "total_MEM": np.uint64,
    "buff": np.uint64,
    "cache": np.uint64,
}

SUM_PIDSTAT_COLS = [
    "percent_CPU",
    # "percent_MEM",
    "total_MEM",
    "buff",
    "cache",
]

_TEMP_DIRS = []


def _cleanup_temp_dirs() -> None:
    """Delete all temporary directories stored in _TEMP_DIRS."""
    for path in _TEMP_DIRS:
        try:
            shutil.rmtree(path, ignore_errors=True)
        except Exception as e:
            print(f"Failed to delete temp dir {path}: {e}")


# Register cleanup function once
atexit.register(_cleanup_temp_dirs)


class Event(ABC):
    """Abstract base class for events with a timestamp."""

    @property
    @abstractmethod
    def time(self) -> np.uint64:
        """Timestamp of the event in milliseconds."""
        pass


class FlowStartEvent(Event):
    """Event for the start of a flow."""

    data_rate: float
    packet_rate: float
    time: np.uint64 = 0
    flow_rate: float
    flows: int

    def __init__(
        self,
        data_rate: float,
        packet_rate: float,
        start_time: np.uint64,
        flow_rate: float,
        flows: int,
    ) -> None:
        """
        Args:
            data_rate: Data rate in bits per second
            packet_rate: Packet rate in packets per second
            start_time: Start time in ms
            flow_rate: Flows per second
            flows: Number of flows
        """
        self.data_rate = data_rate
        self.packet_rate = packet_rate
        self.time = start_time
        self.flow_rate = flow_rate
        self.flows = flows


class FlowEndEvent(Event):
    """Event for the end of a flow."""

    data_rate: float
    packet_rate: float
    time: np.uint64 = 0
    flow_rate: float
    flows: int
    active_time: np.uint64
    cache_time: np.uint64

    def __init__(
        self,
        data_rate: float,
        packet_rate: float,
        end_time: np.uint64,
        flow_rate: float,
        flows: int,
        active_time: np.uint64,
        cache_time: np.uint64,
    ) -> None:
        """
        Args:
            data_rate: Data rate in bits per second (negated)
            packet_rate: Packet rate in packets per second (negated)
            end_time: End time in ms
            flow_rate: Flows per second (negated)
            flows: Number of flows (negated)
            active_time: Active time of the flow
            cache_time: Time in cache
        """
        self.data_rate = -data_rate
        self.packet_rate = -packet_rate
        self.time = end_time
        self.flow_rate = -flow_rate
        self.flows = -int(flows)
        self.active_time = active_time
        self.cache_time = cache_time


class OnePacketFlow(Event):
    """Event for a flow with only one packet."""

    bytes: np.uint64
    packets: np.uint64
    time: np.uint64 = 0
    flows: np.uint64
    active_time: np.uint64
    cache_time: np.uint64

    def __init__(
        self,
        bytes: np.uint64,
        packets: np.uint64,
        time: np.uint64,
        flows: np.uint64,
        active_time: np.uint64,
        cache_time: np.uint64,
    ) -> None:
        """
        Args:
            bytes: Number of bytes
            packets: Number of packets
            time: Timestamp
            flows: Number of flows
            active_time: Active time
            cache_time: Time in cache
        """
        self.bytes = bytes
        self.packets = packets
        self.time = time
        self.flows = flows
        self.active_time = active_time
        self.cache_time = cache_time


class ExportEvent(Event):
    """Event for an export operation."""

    flows: np.uint64
    bytes: np.uint64
    time: np.uint64 = 0

    def __init__(
        self, export_time: np.uint64, flows: np.uint64, bits: np.uint64
    ) -> None:
        """
        Args:
            export_time: Export time in seconds
            flows: Number of flows
            bits: Number of bits
        """
        self.time = export_time * 1000
        self.flows = flows
        self.bytes = bits / np.uint64(8)


class HostStatsEvent(Event):
    """Event holding statistics fetched from the host operating system.

    Example header of the original CSV file:
        Time;UID;PID;percent_usr;percent_system;percent_guest;percent_wait;percent_CPU;CPU;minflt/s;majflt/s;VSZ;RSS;percent_MEM;StkSize;StkRef;threads;fd-nr;Command
    """

    time: np.uint64 = 0

    def __init__(self, row: Any) -> None:
        """
        Args:
            row: Row from DataFrame with host statistics
        """
        self.row = row
        self.time = row.Time * 1000


def merge_sorted(
    temp_files: list[os.PathLike],
    sort_column: str,
    dtype: dict[str, Callable[[Any], Any]],
) -> Iterator[dict[str, object]]:
    """
    Merge multiple pre-sorted CSV files into an iterator, sorted by a column.

    Args:
        temp_files: List of file paths to temporary CSV files
        sort_column: Name of the column to sort by
        dtype: Dictionary with type converters for the columns

    Yields:
        Rows as dictionary with converted types
    """
    file_iters: list[csv.DictReader] = []
    open_files: list[TextIOWrapper] = []
    for f in temp_files:
        file = open(f, "r")
        reader = csv.DictReader(file)
        file_iters.append(reader)
        open_files.append(file)

    def row_key(row: dict[str, str]) -> Any:
        return dtype.get(sort_column, int)(row[sort_column])

    def convert_row_types(row: dict[str, str]) -> dict[str, object]:
        return {key: dtype.get(key, str)(value) for key, value in row.items()}

    for row in heapq.merge(*file_iters, key=row_key):
        yield convert_row_types(row)

    for f in open_files:
        f.close()

    for f in temp_files:
        os.remove(f)


def create_event_queue(
    flows_path: os.PathLike,
    hosts_stats_file: os.PathLike,
    inactive_timeout: int = 30,
    out_dir: os.PathLike = None,
) -> Iterator[Event]:
    """
    Create an iterator over all events generated from flows and host statistics.

    Args:
        flows_path: Path to CSV file with flows
        hosts_stats_file: Path to CSV file with host statistics
        inactive_timeout: Timeout for inactive flows (seconds)
        out_dir: Optional output directory for temporary files

    Returns:
        Iterator over Event objects, sorted by time
    """
    if not out_dir:
        out_dir = tempfile.mkdtemp(prefix="flows_split_")
        _TEMP_DIRS.append(out_dir)

    if not hosts_stats_file:
        hosts_stats_file = tempfile.NamedTemporaryFile(suffix=".csv", dir=out_dir).name
        with open(hosts_stats_file, "x") as f:
            f.write(";".join(STATS_CSV_COLUMN_TYPES.keys()))

    tmp_start_time = []
    tmp_end_time = []
    tmp_one_pack = []
    tmp_export = []

    agg_dict = {
        "PACKETS": ("PACKETS", "sum"),
        "BYTES": ("BYTES", "sum"),
        "FLOWS": ("PACKETS", "count"),
    }

    with open(flows_path, "r") as f:
        header_line = f.readline()

    wanted_columns = set(CSV_COLUMN_TYPES.keys())
    available_columns = set(header_line.strip().split(","))

    start = float("inf")
    end = float("-inf")

    # Load split and presort in chunks
    for chunk in pd.read_csv(
        flows_path,
        dtype=CSV_COLUMN_TYPES,
        usecols=wanted_columns & available_columns,
        chunksize=1_000_000,
    ):
        # get start and end
        start = min(start, math.floor(chunk["START_TIME"].min() / 1000))
        if "EXPORT_TIME" in chunk.columns:
            end = max(end, math.ceil(chunk["EXPORT_TIME"].max()))
        else:
            end = max(end, math.ceil(chunk["END_TIME"].max() / 1000))

        # Export Events
        if "EXPORT_TIME" not in chunk.columns:
            # accurate expected EXPORT_TIME
            chunk["EXPORT_TIME"] = chunk["END_TIME"] // 1000 + inactive_timeout + 1
            # approximate SEQ_NUMBER
            chunk["SEQ_NUMBER"] = chunk["EXPORT_TIME"] % 32
            # random MSG_LENGTH
            chunk["MSG_LENGTH"] = random.randint(100, 2048)
        chunk["ACTIVE_TIME"] = chunk["END_TIME"] - chunk["START_TIME"] + 1
        chunk["CACHE_TIME"] = (
            chunk["EXPORT_TIME"] * 1000 - chunk["START_TIME"] + 1
        ).clip(lower=0)

        with tempfile.NamedTemporaryFile(
            mode="w", prefix="one_packet", suffix=".csv", dir=out_dir, delete=False
        ) as temp_one:
            tmp_one_pack.append(temp_one.name)
            # One-packet flows
            (
                chunk[chunk["START_TIME"] == chunk["END_TIME"]]
                .groupby(["START_TIME", "ACTIVE_TIME", "CACHE_TIME"], as_index=False)
                .agg(**agg_dict)
                .sort_values("START_TIME")
                .to_csv(
                    temp_one,
                    index=False,
                )
            )

        with tempfile.NamedTemporaryFile(
            mode="w", prefix="export_time", suffix=".csv", dir=out_dir, delete=False
        ) as temp_export:
            tmp_export.append(temp_export.name)
            (
                chunk.groupby(["EXPORT_TIME", "SEQ_NUMBER"], as_index=False)
                .agg(
                    MSG_LENGTH=("MSG_LENGTH", "first"),
                    FLOWS=("MSG_LENGTH", "count"),
                )
                .sort_values("EXPORT_TIME")
                .to_csv(
                    temp_export.name,
                    index=False,
                )
            )

        with tempfile.NamedTemporaryFile(
            mode="w", prefix="start_time", suffix=".csv", dir=out_dir, delete=False
        ) as temp_start:
            tmp_start_time.append(temp_start.name)
            # Multi-packet flows
            (
                chunk[chunk["START_TIME"] != chunk["END_TIME"]]
                .groupby(
                    ["START_TIME", "END_TIME", "ACTIVE_TIME", "CACHE_TIME"],
                    as_index=False,
                )
                .agg(**agg_dict)
                .sort_values("START_TIME")
                .to_csv(
                    temp_start.name,
                    index=False,
                )
            )

        with tempfile.NamedTemporaryFile(
            mode="w", prefix="end_time", suffix=".csv", dir=out_dir, delete=False
        ) as temp_end:
            tmp_end_time.append(temp_end.name)
            (
                chunk[chunk["START_TIME"] != chunk["END_TIME"]]
                .groupby(
                    ["START_TIME", "END_TIME", "ACTIVE_TIME", "CACHE_TIME"],
                    as_index=False,
                )
                .agg(**agg_dict)
                .sort_values("END_TIME")
                .to_csv(
                    temp_end.name,
                    index=False,
                )
            )

    temp_stats = tempfile.NamedTemporaryFile(
        mode="w", prefix="host_stats_", suffix=".csv", dir=out_dir, delete=False
    )

    try:
        stats_df: pd.DataFrame = pd.read_csv(
            hosts_stats_file,
            sep=";",
            dtype=STATS_CSV_COLUMN_TYPES,
            engine="pyarrow",
            usecols=STATS_CSV_COLUMN_TYPES.keys(),
        )
        stats_df = stats_df[(stats_df["Time"] >= start) & (stats_df["Time"] <= end)]
    except Exception:
        stats_df = pd.DataFrame([], columns=STATS_CSV_COLUMN_TYPES.keys())

    stats_df.to_csv(temp_stats, sep=";", index=False)
    temp_stats.close()

    return heapq.merge(
        read_one_packet_events(tmp_one_pack),
        read_start_events(tmp_start_time),
        read_end_events(tmp_end_time),
        read_export_events(tmp_export),
        read_host_stats_events(temp_stats.name),
        key=lambda e: e.time,
    )


def read_export_events(path: os.PathLike) -> Iterator[ExportEvent]:
    previous = None
    for row in merge_sorted(
        path,
        "EXPORT_TIME",
        {
            "EXPORT_TIME": np.uint64,
            "SEQ_NUMBER": np.uint32,
            "FLOWS": np.uint64,
            "MSG_LENGTH": np.uint64,
        },
    ):
        # It's possilble that columns weren't merged because of chunked reads
        # merge here where columns are iterated by EXPORT_TIME
        if not previous:
            previous = row
            continue
        if (
            previous["EXPORT_TIME"] == row["EXPORT_TIME"]
            and previous["SEQ_NUMBER"] == row["SEQ_NUMBER"]
        ):
            previous["FLOWS"] += row["FLOWS"]
            continue
        yield ExportEvent(
            bits=previous["MSG_LENGTH"],
            flows=previous["FLOWS"],
            export_time=previous["EXPORT_TIME"],
        )
        previous = row
    if previous:
        yield ExportEvent(
            bits=previous["MSG_LENGTH"],
            flows=previous["FLOWS"],
            export_time=previous["EXPORT_TIME"],
        )


def read_host_stats_events(path: os.PathLike) -> Iterator[HostStatsEvent]:
    for chunk in pd.read_csv(
        path,
        chunksize=100_000,
        sep=";",
        dtype=STATS_CSV_COLUMN_TYPES,
        usecols=STATS_CSV_COLUMN_TYPES.keys(),
    ):
        for row in chunk.itertuples(index=False):
            yield HostStatsEvent(row)


def read_one_packet_events(path: os.PathLike) -> Iterator[OnePacketFlow]:
    CSV_AGGREGATE_TYPES_NO_END = {
        k: v for k, v in CSV_AGGREGATE_TYPES.items() if k != "END_TIME"
    }
    for row in merge_sorted(path, "START_TIME", CSV_AGGREGATE_TYPES_NO_END):
        yield OnePacketFlow(
            bytes=row["BYTES"],
            packets=row["PACKETS"],
            time=row["START_TIME"],
            flows=row["FLOWS"],
            active_time=row["ACTIVE_TIME"],
            cache_time=row["CACHE_TIME"],
        )


def read_start_events(path: os.PathLike) -> Iterator[FlowStartEvent]:
    for row in merge_sorted(path, "START_TIME", CSV_AGGREGATE_TYPES):
        duration = (row["END_TIME"] - row["START_TIME"] + 1) / 1_000
        data_rate = row["BYTES"] * 8 / duration
        packet_rate = row["PACKETS"] / duration
        flow_rate = row["FLOWS"] / duration
        yield FlowStartEvent(
            data_rate=data_rate,
            packet_rate=packet_rate,
            start_time=np.uint64(row["START_TIME"]),
            flow_rate=flow_rate,
            flows=row["FLOWS"],
        )


def read_end_events(path: os.PathLike) -> Iterator[FlowEndEvent]:
    for row in merge_sorted(path, "END_TIME", CSV_AGGREGATE_TYPES):
        duration = (row["END_TIME"] - row["START_TIME"] + 1) / 1_000
        data_rate = row["BYTES"] * 8 / duration
        packet_rate = row["PACKETS"] / duration
        flow_rate = row["FLOWS"] / duration
        yield FlowEndEvent(
            data_rate=data_rate,
            packet_rate=packet_rate,
            end_time=row["END_TIME"],
            flow_rate=flow_rate,
            flows=row["FLOWS"],
            active_time=row["ACTIVE_TIME"],
            cache_time=row["CACHE_TIME"],
        )
