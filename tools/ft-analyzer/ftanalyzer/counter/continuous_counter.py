import numpy as np
from .counter import Counter
from ..statistic_object import SimState


class ContinuousCounter(Counter):
    def __init__(
        self,
        variable: str,
        sim: SimState,
        factor: float = 1,
        has_negatives: bool = False,
        measure_start_time: np.uint64 = None,
        measure_end_time: np.uint64 = None,
    ) -> None:
        """
        Initialize a continuous-time counter.
        Args:
            variable: Name of the observed variable.
            sim: Simulation state object.
            factor: Scaling factor for values.
            has_negatives: If True, allow negative values for min.
            measure_start_time: Start time for measurement window.
            measure_end_time: End time for measurement window.
        """
        super().__init__(
            variable, "counter type: continuous-time counter", has_negatives
        )
        if not measure_start_time:
            measure_start_time = sim.get_time()
        if not measure_end_time:
            measure_end_time = np.infty
        self._measure_start_time = measure_start_time
        self._measure_end_time = measure_end_time
        self.last_sample_time: np.uint64 = np.uint64(0)
        self.first_sample_time: np.uint64 = np.uint64(0)
        self.last_sample_size: np.float64 = np.float64(0)
        self._factor = factor
        self._sim = sim

    def get_mean(self) -> np.float64:
        """
        Returns the mean value over the measurement interval.
        Returns:
            Mean value as np.float64.
        """
        interval = self.last_sample_time - self.first_sample_time
        if interval > 0:
            return np.float64(self.get_sum_power_one()) / np.float64(interval)
        else:
            return np.float64(0)

    def get_variance(self) -> np.float64:
        """
        Returns the variance over the measurement interval.
        Returns:
            Variance as np.float64.
        """
        interval = self.last_sample_time - self.first_sample_time
        if interval > 0:
            mean = self.get_mean()
            variance = (
                np.float64(self.get_sum_power_two()) / np.float64(interval)
            ) - mean * mean
            return variance

        else:
            return np.float64(0)

    def count(self, x: np.float64) -> None:
        """
        Count a new sample, updating statistics with time-weighted increments.
        Args:
            x: Value to count.
        """
        if (
            self._sim.get_time() < self._measure_start_time
            or self._sim.get_time() > self._measure_end_time
        ):
            return
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
        """
        Reset all statistics and measurement window.
        """
        super().reset()
        self.first_sample_time = self._sim.get_time()
        self.last_sample_time = self._sim.get_time()
        self.last_sample_size = np.float64(0)
