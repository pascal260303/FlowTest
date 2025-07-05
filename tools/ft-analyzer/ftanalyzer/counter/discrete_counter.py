from .counter import Counter
import numpy as np

class DiscreteCounter(Counter):
    """
    Implements a discrete time counter, which updates statistics per discrete
    observation.
    """

    def __init__(self, variable: str, counter_type: str = "counter type: discrete-time counter"):
        """
        Constructor for DiscreteCounter.

        Args:
            variable (str): Name of the observed variable
            counter_type (str, optional): Counter type label. Defaults to discrete-time counter.
        """
        super().__init__(variable, counter_type)

    def get_mean(self) -> np.float64:
        """
        Computes the mean of the observed variable over samples.

        Returns:
            np.float64: the mean value
        """
        if self.get_num_samples() > 0:
            return np.float64(self.get_sum_power_one()) / np.float64(self.get_num_samples())
        else:
            return np.float64(0)

    def get_variance(self) -> np.float64:
        """
        Computes the sample variance of the observed variable.

        Returns:
            np.float64: the variance
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
        Counts a new observation and updates first/second moments.

        Args:
            x (np.float64): the observation
        """
        super().count(x)
        self.increase_sum_power_one(x)
        self.increase_sum_power_two(x * x)
