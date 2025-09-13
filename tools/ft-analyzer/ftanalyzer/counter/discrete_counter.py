from .counter import Counter
import numpy as np


class DiscreteCounter(Counter):
    """
    Implements a discrete time counter, updating statistics per observation.
    """

    def __init__(
        self, variable: str, counter_type: str = "counter type: discrete-time counter"
    ) -> None:
        """
        Initialize a discrete time counter.
        Args:
            variable: Name of the observed variable.
            counter_type: Counter type label.
        """
        super().__init__(variable, counter_type)

    def get_mean(self) -> np.float64:
        """
        Compute the mean of the observed variable over samples.
        Returns:
            Mean value as np.float64.
        """
        if self.get_num_samples() > 0:
            return np.float64(self.get_sum_power_one()) / np.float64(
                self.get_num_samples()
            )
        else:
            return np.float64(0)

    def get_variance(self) -> np.float64:
        """
        Compute the sample variance of the observed variable.
        Returns:
            Variance as np.float64.
        """
        n = self.get_num_samples()
        if n > 1:
            mean = self.get_mean()
            return (n / np.float64(n - 1)) * (
                self.get_sum_power_two() / np.float64(n) - mean * mean
            )
        else:
            return np.float64(0)

    def count(self, x: np.float64) -> None:
        """
        Count a new observation and update first/second moments.
        Args:
            x: The observation value.
        """
        super().count(x)
        self.increase_sum_power_one(x)
        self.increase_sum_power_two(x * x)
