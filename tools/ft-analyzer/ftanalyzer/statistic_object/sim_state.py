import numpy as np


class SimState:
    _time: np.uint64

    def __init__(self, start_time: np.uint64 = np.uint64(0)):
        self._time = start_time

    def set_time(self, time):
        self._time = np.uint64(time)

    def get_time(self) -> np.uint64:
        return self._time

    def get_time_seconds(self) -> np.float64:
        return self.convert_to_seconds(self._time)

    def get_time_diff(self, time) -> np.uint64:
        return np.uint64(abs(int(self._time) - int(time)))

    def convert_to_seconds(self, time) -> np.float64:
        return np.float64(time) / 10**3
