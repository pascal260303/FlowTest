from abc import ABC, abstractmethod
from typing import List
import numpy as np
import pandas as pd


class Event(ABC):
    @property
    @abstractmethod
    def time(self) -> np.uint64:
        pass


class FlowStartEvent(Event):
    data_rate: float
    packet_rate: float
    time = 0

    def __init__(self, data_rate, packet_rate, start_time):
        self.data_rate = data_rate
        self.packet_rate = packet_rate
        self.time = start_time


class FlowEndEvent(Event):
    data_rate: float
    packet_rate: float
    time = 0

    def __init__(self, data_rate, packet_rate, end_time):
        self.data_rate = -data_rate
        self.packet_rate = -packet_rate
        self.time = end_time


class OnePacketFlow(Event):
    bytes: np.uint64
    packets: np.uint64
    time = 0

    def __init__(self, bytes, packets, time):
        self.bytes = bytes
        self.packets = packets
        self.time = time


def create_event_queue(flow_df: pd.DataFrame) -> List[Event]:
    events: List[Event] = []

    # Split flows
    one_packet_mask = flow_df["PACKETS"] == 1
    one_packet_flows = flow_df[one_packet_mask]
    multi_packet_flows = flow_df[~one_packet_mask]

    # Process one-packet flows
    if not one_packet_flows.empty:
        bytes_arr = one_packet_flows["BYTES"].to_numpy()
        packets_arr = one_packet_flows["PACKETS"].to_numpy()
        times_arr = one_packet_flows["START_TIME"].to_numpy()

        events.extend(
            [
                OnePacketFlow(bytes=b, packets=p, time=t)
                for b, p, t in zip(bytes_arr, packets_arr, times_arr)
            ]
        )

    # Process multi-packet flows
    if not multi_packet_flows.empty:
        start_times = multi_packet_flows["START_TIME"].to_numpy()
        end_times = multi_packet_flows["END_TIME"].to_numpy()
        bytes_arr = multi_packet_flows["BYTES"].to_numpy()
        packets_arr = multi_packet_flows["PACKETS"].to_numpy()

        durations_s = (end_times - start_times + 1) / 1_000  # convert ms to s
        data_rates = (bytes_arr * 8) / durations_s  # bits per second
        packet_rates = packets_arr / durations_s

        # Add FlowStartEvents
        events.extend(
            [
                FlowStartEvent(data_rate=dr, packet_rate=pr, start_time=st)
                for dr, pr, st in zip(data_rates, packet_rates, start_times)
            ]
        )

        # Add FlowEndEvents
        events.extend(
            [
                FlowEndEvent(data_rate=dr, packet_rate=pr, end_time=et)
                for dr, pr, et in zip(data_rates, packet_rates, end_times)
            ]
        )

    # Sort events by timestamp (in-place)
    events.sort(key=lambda e: e.time)
    return events
