from abc import ABC, abstractmethod
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
        self.data_rate = data_rate
        self.packet_rate = packet_rate
        self.time = end_time


class OnePacketFlow(Event):
    bytes: np.uint64
    packets: np.uint64
    time = 0
    
    def __init__(self, bytes, packets, time):
        self.bytes = bytes
        self.packets = packets
        self.time = time

def create_event_queue(flow_df: pd.DataFrame) -> list[Event]:
    events: list[Event] = []
    
    # split one-packet and multi-packet
    one_packet_mask = flow_df["PACKETS"] == 1
    
    one_packet_flows = flow_df.loc[one_packet_mask]
    multi_packet_flows = flow_df.loc[~one_packet_mask]
    
    # handle one-packet flows
    if not one_packet_flows.empty:
        events.extend([
            OnePacketFlow(
                bytes=row.BYTES,
                packets=row.PACKETS,
                time=row.START_TIME
            )
            for row in one_packet_flows.itertuples(index=False)
        ])
    
    # handle multi-packet flows
    if not multi_packet_flows.empty:
        durations = (multi_packet_flows["END_TIME"] - multi_packet_flows["START_TIME"] + 1) / 10**3
        data_rates = (multi_packet_flows["BYTES"] * 8) / durations
        packet_rates = multi_packet_flows["PACKETS"] / durations
        
        # FlowStartEvents
        events.extend([
            FlowStartEvent(
                data_rate=dr,
                packet_rate=pr,
                start_time=st
            )
            for dr, pr, st in zip(
                data_rates,
                packet_rates,
                multi_packet_flows["START_TIME"]
            )
        ])
        
        # FlowEndEvents
        events.extend([
            FlowEndEvent(
                data_rate=dr,
                packet_rate=pr,
                end_time=et
            )
            for dr, pr, et in zip(
                data_rates,
                packet_rates,
                multi_packet_flows["END_TIME"]
            )
        ])
    
    # sort by time
    return sorted(events, key=lambda e: e.time)

    
    
            
    
