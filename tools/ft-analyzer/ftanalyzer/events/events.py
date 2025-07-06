from abc import ABC, abstractmethod
import atexit
import heapq
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
}

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

    def __init__(self, data_rate, packet_rate, start_time, flow_rate):
        self.data_rate = data_rate
        self.packet_rate = packet_rate
        self.time = start_time
        self.flow_rate = flow_rate


class FlowEndEvent(Event):
    data_rate: float
    packet_rate: float
    time = 0
    flow_rate: float

    def __init__(self, data_rate, packet_rate, end_time, flow_rate):
        self.data_rate = -data_rate
        self.packet_rate = -packet_rate
        self.time = end_time
        self.flow_rate = -flow_rate


class OnePacketFlow(Event):
    bytes: np.uint64
    packets: np.uint64
    time = 0

    def __init__(self, bytes, packets, time):
        self.bytes = bytes
        self.packets = packets
        self.time = time


def create_event_queue(flows_csv_path: str, out_dir: str = None) -> Iterator[Event]:
    if not out_dir:
        tempfile.mkdtemp(prefix="flows_split_")
        _TEMP_DIRS.append(out_dir)

    # Paths for output CSVs
    one_packet_path = os.path.join(out_dir, "flows_one_packet.csv")
    sorted_by_start_path = os.path.join(out_dir, "flows_sorted_by_start.csv")
    sorted_by_end_path = os.path.join(out_dir, "flows_sorted_by_end.csv")

    # Load and split
    df = pd.read_csv(flows_csv_path, dtype=CSV_COLUMN_TYPES)

    # One-packet flows
    one_packet_df = df[df["PACKETS"] == 1].sort_values("START_TIME")
    one_packet_df.to_csv(one_packet_path, index=False)

    # Multi-packet flows
    multi_df = df[df["PACKETS"] > 1]
    multi_df.sort_values("START_TIME").to_csv(sorted_by_start_path, index=False)
    multi_df.sort_values("END_TIME").to_csv(sorted_by_end_path, index=False)

    return heapq.merge(
        read_one_packet_events(one_packet_path),
        read_start_events(sorted_by_start_path),
        read_end_events(sorted_by_end_path),
        key=lambda e: e.time,
    )


def read_one_packet_events(path: str) -> Iterator[OnePacketFlow]:
    for chunk in pd.read_csv(path, dtype=CSV_COLUMN_TYPES, chunksize=100_000):
        for row in chunk.itertuples(index=False):
            yield OnePacketFlow(
                bytes=np.uint64(row.BYTES),
                packets=np.uint64(row.PACKETS),
                time=np.uint64(row.START_TIME),
            )


def read_start_events(path: str) -> Iterator[FlowStartEvent]:
    for chunk in pd.read_csv(path, dtype=CSV_COLUMN_TYPES, chunksize=100_000):
        durations = (chunk.END_TIME - chunk.START_TIME + 1) / 1_000
        data_rates = (chunk.BYTES * 8) / durations
        packet_rates = chunk.PACKETS / durations
        flow_rates = 1 / durations
        for row, dr, pr, fr in zip(
            chunk.itertuples(index=False), data_rates, packet_rates, flow_rates
        ):
            yield FlowStartEvent(
                data_rate=dr,
                packet_rate=pr,
                start_time=np.uint64(row.START_TIME),
                flow_rate=fr,
            )


def read_end_events(path: str) -> Iterator[FlowEndEvent]:
    for chunk in pd.read_csv(path, dtype=CSV_COLUMN_TYPES, chunksize=100_000):
        durations = (chunk.END_TIME - chunk.START_TIME + 1) / 1_000
        data_rates = (chunk.BYTES * 8) / durations
        packet_rates = chunk.PACKETS / durations
        flow_rates = 1 / durations
        for row, dr, pr, fr in zip(
            chunk.itertuples(index=False), data_rates, packet_rates, flow_rates
        ):
            yield FlowEndEvent(
                data_rate=dr,
                packet_rate=pr,
                end_time=np.uint64(row.END_TIME),
                flow_rate=fr,
            )
