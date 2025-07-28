from abc import ABC, abstractmethod
import atexit
import heapq
import math
import os
import shutil
import tempfile
from typing import Iterator
import numpy as np
import pandas as pd

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

CSV_AGGREGATE_TYPES = {
    "START_TIME": np.uint64,
    "END_TIME": np.uint64,
    "PACKETS": np.uint64,
    "BYTES": np.uint64,
    "FLOWS": np.uint64,
}

STATS_CSV_COLUMN_TYPES = {
    "Time": np.uint64,
    "UID": np.uint64,
    "PID": np.uint64,
    "percent_usr": np.float64,
    "percent_system": np.float64,
    "percent_guest": np.float64,
    "percent_wait": np.float64,
    "percent_CPU": np.float64,
    "CPU": np.uint64,
    "minflt/s": np.float64,
    "majflt/s": np.float64,
    "VSZ": np.uint64,
    "RSS": np.uint64,
    "percent_MEM": np.float64,
    "StkSize": np.uint64,
    "StkRef": np.uint64,
    "threads": np.uint64,
    "fd-nr": np.uint64,
    "Command": str,
}

SUM_PIDSTAT_COLS = [
    "percent_usr",
    "percent_system",
    "percent_guest",
    "percent_wait",
    "percent_CPU",
    "minflt/s",
    "majflt/s",
    "fd-nr",
]
TAKE_PIDSTAT_COLS = [
    "RSS",
    "VSZ",
    "percent_MEM",
    "threads",
    "UID",
    "Command",
    "CPU",
    "Time",
]

_TEMP_DIRS = []


def _cleanup_temp_dirs():
    for path in _TEMP_DIRS:
        try:
            shutil.rmtree(path, ignore_errors=True)
        except Exception as e:
            print(f"Failed to delete temp dir {path}: {e}")


# Register cleanup function once
atexit.register(_cleanup_temp_dirs)


class Event(ABC):
    @property
    @abstractmethod
    def time(self) -> np.uint64:
        pass


class FlowStartEvent(Event):
    data_rate: float
    packet_rate: float
    time = 0
    flow_rate: float
    flows: int

    def __init__(self, data_rate, packet_rate, start_time, flow_rate, flows):
        self.data_rate = data_rate
        self.packet_rate = packet_rate
        self.time = start_time
        self.flow_rate = flow_rate
        self.flows = flows


class FlowEndEvent(Event):
    data_rate: float
    packet_rate: float
    time = 0
    flow_rate: float
    flows: int

    def __init__(self, data_rate, packet_rate, end_time, flow_rate, flows):
        self.data_rate = -data_rate
        self.packet_rate = -packet_rate
        self.time = end_time
        self.flow_rate = -flow_rate
        self.flows = -flows


class OnePacketFlow(Event):
    bytes: np.uint64
    packets: np.uint64
    time = 0
    flows: np.uint64

    def __init__(self, bytes, packets, time, flows):
        self.bytes = bytes
        self.packets = packets
        self.time = time
        self.flows = flows


class ExportEvent(Event):
    flows: np.uint64
    bytes: np.uint64
    time = 0

    def __init__(self, export_time, flows, bits):
        self.time = export_time * 1000
        self.flows = flows
        self.bytes = bits / np.uint64(8)


class HostStatsEvent(Event):
    """Event Holding Statistics fetched from Host OS

    Example header of original csv file:
        Time;UID;PID;percent_usr;percent_system;percent_guest;percent_wait;percent_CPU;CPU;minflt/s;majflt/s;VSZ;RSS;percent_MEM;StkSize;StkRef;threads;fd-nr;Command
    """

    time = 0

    def __init__(self, row):
        self.row = row
        self.time = row.Time * 1000


def create_event_queue(
    flows_csv_path: os.PathLike, hosts_stats_file: os.PathLike, out_dir: str = None
) -> Iterator[Event]:
    if not out_dir:
        out_dir = tempfile.mkdtemp(prefix="flows_split_")
        _TEMP_DIRS.append(out_dir)

    if not hosts_stats_file:
        hosts_stats_file = tempfile.NamedTemporaryFile(suffix=".csv", dir=out_dir).name
        with open(hosts_stats_file, "x") as f:
            f.write(";".join(STATS_CSV_COLUMN_TYPES.keys()))

    # Paths for output CSVs
    one_packet_path = os.path.join(out_dir, "flows_one_packet.csv")
    sorted_by_start_path = os.path.join(out_dir, "flows_sorted_by_start.csv")
    sorted_by_end_path = os.path.join(out_dir, "flows_sorted_by_end.csv")
    sorted_by_export_path = os.path.join(out_dir, "flows_sorted_by_export.csv")

    # Load and split
    df = pd.read_csv(flows_csv_path, dtype=CSV_COLUMN_TYPES)
    df.fillna(0)

    # Filer host stats file by time
    start = math.floor(df["START_TIME"].min() / 1000)
    end = math.ceil(df["END_TIME"].max() / 1000)

    stats_df: pd.DataFrame = pd.read_csv(
        hosts_stats_file, sep=";", dtype=STATS_CSV_COLUMN_TYPES
    )
    stats_df = stats_df[(stats_df["Time"] >= start) & (stats_df["Time"] <= end)]

    agg_dict = {col: "sum" for col in SUM_PIDSTAT_COLS}
    agg_dict.update({col: "first" for col in TAKE_PIDSTAT_COLS})
    stats_df = stats_df.groupby(["Time"]).agg(agg_dict)

    stats_df.to_csv(hosts_stats_file, sep=";", index=False)

    agg_dict = {
        "PACKETS": ("PACKETS", "sum"),
        "BYTES": ("BYTES", "sum"),
        "FLOWS": ("PACKETS", "count"),
    }
    # One-packet flows
    (
        df[df["PACKETS"] == 1]
        .groupby("START_TIME", as_index=False)
        .agg(**agg_dict)
        .sort_values("START_TIME")
        .to_csv(one_packet_path, index=False)
    )

    # Multi-packet flows
    multi_df = (
        df[df["PACKETS"] > 1]
        .groupby(["START_TIME", "END_TIME"], as_index=False)
        .agg(**agg_dict)
    )
    multi_df.sort_values("START_TIME").to_csv(sorted_by_start_path, index=False)
    multi_df.sort_values("END_TIME").to_csv(sorted_by_end_path, index=False)

    # Export Events
    if "EXPORT_TIME" in df.columns:
        df.groupby(["EXPORT_TIME", "SEQ_NUMBER"], as_index=False).agg(
            MSG_LENGTH=("MSG_LENGTH", "first"),
            FLOWS=("MSG_LENGTH", "count"),
        ).sort_values("EXPORT_TIME").to_csv(sorted_by_export_path, index=False)
    else:
        with open(sorted_by_export_path, "w+") as f:
            f.write("EXPORT_TIME,SEQ_NUMBER,FLOWS,MSG_LENGTH")

    return heapq.merge(
        read_one_packet_events(one_packet_path),
        read_start_events(sorted_by_start_path),
        read_end_events(sorted_by_end_path),
        read_export_events(sorted_by_export_path),
        read_host_stats_events(hosts_stats_file),
        key=lambda e: e.time,
    )


def read_export_events(path: os.PathLike):
    for chunk in pd.read_csv(
        path,
        dtype={
            "EXPORT_TIME": np.uint64,
            "SEQ_NUMBER": np.uint32,
            "FLOWS": np.uint64,
            "MSG_LENGTH": np.uint64,
        },
        chunksize=100_000,
    ):
        for row in chunk.itertuples(index=False):
            yield ExportEvent(
                bits=np.uint64(row.MSG_LENGTH),
                flows=np.uint64(row.FLOWS),
                export_time=np.uint64(row.EXPORT_TIME),
            )


def read_host_stats_events(path: os.PathLike):
    for chunk in pd.read_csv(
        path, chunksize=100_000, sep=";", dtype=STATS_CSV_COLUMN_TYPES
    ):
        for row in chunk.itertuples(index=False):
            yield HostStatsEvent(row)


def read_one_packet_events(path: str) -> Iterator[OnePacketFlow]:
    CSV_AGGREGATE_TYPES_NO_END = {
        k: v for k, v in CSV_AGGREGATE_TYPES.items() if k != "END_TIME"
    }
    for chunk in pd.read_csv(path, dtype=CSV_AGGREGATE_TYPES_NO_END, chunksize=100_000):
        for row in chunk.itertuples(index=False):
            yield OnePacketFlow(
                bytes=np.uint64(row.BYTES),
                packets=np.uint64(row.PACKETS),
                time=np.uint64(row.START_TIME),
                flows=row.FLOWS,
            )


def read_start_events(path: str) -> Iterator[FlowStartEvent]:
    for chunk in pd.read_csv(path, dtype=CSV_AGGREGATE_TYPES, chunksize=100_000):
        durations = (chunk.END_TIME - chunk.START_TIME + 1) / 1_000
        data_rates = (chunk.BYTES * 8) / durations
        packet_rates = chunk.PACKETS / durations
        flow_rates = chunk.FLOWS / durations
        for row, dr, pr, fr in zip(
            chunk.itertuples(index=False), data_rates, packet_rates, flow_rates
        ):
            yield FlowStartEvent(
                data_rate=dr,
                packet_rate=pr,
                start_time=np.uint64(row.START_TIME),
                flow_rate=fr,
                flows=row.FLOWS,
            )


def read_end_events(path: str) -> Iterator[FlowEndEvent]:
    for chunk in pd.read_csv(path, dtype=CSV_AGGREGATE_TYPES, chunksize=100_000):
        durations = (chunk.END_TIME - chunk.START_TIME + 1) / 1_000
        data_rates = (chunk.BYTES * 8) / durations
        packet_rates = chunk.PACKETS / durations
        flow_rates = chunk.FLOWS / durations
        for row, dr, pr, fr in zip(
            chunk.itertuples(index=False), data_rates, packet_rates, flow_rates
        ):
            yield FlowEndEvent(
                data_rate=dr,
                packet_rate=pr,
                end_time=np.uint64(row.END_TIME),
                flow_rate=fr,
                flows=row.FLOWS,
            )
