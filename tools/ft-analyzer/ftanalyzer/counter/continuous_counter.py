import numpy as np
from .counter import Counter
from ..statistic_object import SimState


class ContinuousCounter(Counter):
    def __init__(self, variable: str, sim: SimState, factor = 1):
        """Constructor

        Args:
            variable (str): _description_
            start_time (np.uint64, optional): _description_. Defaults to np.uint64(0).
        """
        super().__init__(variable, "counter type: continuous-time counter")
        self.last_sample_time: np.uint64 = np.uint64(0)
        self.first_sample_time: np.uint64 = np.uint64(0)
        self.last_sample_size: np.float64 = np.float64(0)
        self._factor = factor
        self._sim = sim

    def get_mean(self) -> np.float64:
        interval = self.last_sample_time - self.first_sample_time
        if interval > 0:
            return np.float64(self.get_sum_power_one()) / np.float64(interval)
        else:
            return np.float64(0)

    def get_variance(self) -> np.float64:
        interval = self.last_sample_time - self.first_sample_time
        if interval > 0:
            mean = self.get_mean()
            variance = (np.float64(self.get_sum_power_two()) / np.float64(interval)
            ) - mean * mean
            return variance
                
        else:
            return np.float64(0)

    def count(self, x: np.float64) -> None:       
        x = x * self._factor
        super().count(x)
        
        if self.first_sample_time == 0:
            self.first_sample_time = self._sim.get_time()
            self.last_sample_time = self._sim.get_time()
            self.last_sample_size = x
            return
        
        current_time = self._sim.get_time()
        interval = self._sim.get_time_diff(self.last_sample_time)
        self.increase_sum_power_one(self.last_sample_size * interval)
        self.increase_sum_power_two(
            self.last_sample_size * self.last_sample_size * interval
        )
        self.last_sample_size = x
        self.last_sample_time = current_time

    def reset(self) -> None:
        super().reset()
        self.first_sample_time = self._sim.get_time()
        self.last_sample_time = self._sim.get_time()
        self.last_sample_size = np.float64(0)
