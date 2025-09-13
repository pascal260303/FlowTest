from .histogram import Histogram
from abc import ABC
from ..statistic_object import SimState


class ContinuousHistogram(Histogram, ABC):
    """
    Implements a continuous-time histogram for time-weighted observations.
    """

    def __init__(
        self,
        variable: str,
        num_intervals: int,
        lower_bound: float,
        upper_bound: float,
        sim: SimState,
    ) -> None:
        """
        Initialize a continuous-time histogram.
        Args:
            variable: Name of the observed variable.
            num_intervals: Number of bins.
            lower_bound: Lower bound of histogram.
            upper_bound: Upper bound of histogram.
            sim: Simulation state object.
        """
        super().__init__(
            variable,
            num_intervals,
            lower_bound,
            upper_bound,
            histogram_type="histogram type: continuous-time histogram",
        )
        self.first_sample_time = sim.get_time()
        self.last_sample_time = sim.get_time()
        self.last_sample_size = 0.0
        self.sim = sim

    def count(self, x: float) -> None:
        """
        Count a new observation, updating the bin with time-weighted increments.
        Args:
            x: Value to count.
        """
        current_time = self.sim.get_time()
        if self.get_num_intervals() > 0:
            time_delta = current_time - self.last_sample_time
            bin_number = self.get_bin_number(self.last_sample_size)
            self.increment_bin(bin_number, time_delta)
            self.last_sample_time = current_time
        self.last_sample_size = x

    def get_normalizing_factor(self) -> float:
        """
        Return the normalizing factor for the histogram.
        Returns:
            Time interval as float.
        """
        return self.last_sample_time - self.first_sample_time

    def reset(self) -> None:
        """
        Reset the histogram and start fresh.
        """
        super().reset()
        current_time = self.sim.get_time()
        self.first_sample_time = current_time
        self.last_sample_time = current_time
        self.last_sample_size = 0.0
