from typing import List

import numpy as np
from .continuous_counter import ContinuousCounter
from .counter import Counter


class BatchMeansCounter(Counter):
    """
    BatchMeansCounter calculates batch-means statistics from a list of Counter objects (e.g., ContinuousCounter).
    It does not store individual values, but uses the means and variances of the batches.
    """

    def __init__(
        self,
        batch_counters: list[ContinuousCounter],
        variable: str,
        type: str = "counter type: batch-means",
        has_negatives: bool = False,
    ) -> None:
        """
        Initialize a BatchMeansCounter for a given list of batch counters.
        Args:
            batch_counters: List of ContinuousCounter objects representing batches.
            variable: Name of the observed variable.
            type: Description of the counter type.
            has_negatives: If True, allow negative values for min.
        """
        super().__init__(variable, type, has_negatives)
        self.batch_counters = batch_counters
        self.batch_means = None
        self.batch_vars = None

    def get_batch_means(self) -> List[np.float64]:
        """Get the list of means
        Should only be called at the end of the simulation. Triggers the calculation of the means and stores them in a list for later.

        Returns:
            List[np.float64]: List of means
        """
        if self.batch_means is None:
            self.batch_means = [
                c.get_mean() for c in self.batch_counters if c.get_num_samples() != 0
            ]

        return self.batch_means

    def get_batch_vars(self) -> List[np.float64]:
        """Get the list of variances
        Should only be called at the end of the simulation. Triggers the calculation of the variances and stores them in a list for later.

        Returns:
            List[np.float64]: List of variances
        """
        if self.batch_vars is None:
            self.batch_vars = [
                c.get_variance()
                for c in self.batch_counters
                if c.get_num_samples() != 0
            ]

        return self.batch_vars

    def get_mean(self) -> np.float64:
        """
        Returns the mean of batch means (fulfills Counter interface).
        Returns:
            Mean value as np.float64.
        """
        return np.float64(self.mean_of_means())

    def get_variance(self) -> np.float64:
        """
        Returns the variance of batch means (fulfills Counter interface).
        Returns:
            Variance as np.float64.
        """
        return np.float64(self.variance_of_means())

    def get_std_deviation(self) -> np.float64:
        """
        Returns the standard deviation of batch means (fulfills Counter interface).
        Returns:
            Standard deviation as np.float64.
        """
        return np.sqrt(max(self.get_variance(), 0))

    def get_min(self) -> np.float64:
        if self.get_batch_means():
            return min(self.get_batch_means())

        return float("inf")

    def get_max(self) -> np.float64:
        if self.get_batch_means():
            return max(self.get_batch_means())

        return -float("inf")

    def get_num_samples(self) -> np.uint64:
        return len(self.get_batch_means())

    def get_sum_power_one(self) -> np.float64:
        raise NotImplementedError(
            "get_sum_power_one is not defined for BatchMeansCounter."
        )

    def get_sum_power_two(self) -> np.float64:
        raise NotImplementedError(
            "get_sum_power_two is not defined for BatchMeansCounter."
        )

    def count(self, x: np.float64) -> None:
        raise NotImplementedError("count is not defined for BatchMeansCounter.")

    def reset(self) -> None:
        pass

    def mean_of_means(self) -> np.float64:
        """
        Calculates the mean of batch means.
        Returns:
            Mean value as np.float64.
        """
        if self.get_num_samples() == 0:
            return np.nan
        return np.mean(self.get_batch_means())

    def variance_of_means(self) -> np.float64:
        """
        Calculates the variance of batch means.
        Returns:
            Variance as np.float64.
        """
        if self.get_num_samples() == 0:
            return np.nan
        return np.var(self.get_batch_means(), ddof=1)  # empirical variance

    def mean_of_vars(self) -> np.float64:
        """
        Calculates the mean of batch variances.
        Returns:
            Mean value as np.float64.
        """
        if self.get_num_samples() == 0:
            return np.nan
        return np.mean(self.get_batch_vars())

    def report(self) -> str:
        """
        Returns a report of batch-means statistics.
        """
        out = ""
        if self._observed_variable:
            out += f"observed metric: {self._observed_variable}\n"

        out += (
            f"\t{self.get_counter_type()}\n"
            + f"\tnumber of samples: {self.get_num_samples()}\n"
            + f"\tmean: {self.get_mean()}\n"
            + f"\tvariance: {self.get_variance()}\n"
            + f"\tstandard deviation: {self.get_std_deviation()}\n"
            + f"\tcoefficient of variation: {self.get_cvar()}\n"
            + f"\tminimum: {self.get_min()}\n"
            + f"\tmaximum: {self.get_max()}\n"
            + f"\tmean of batch variances: {self.mean_of_vars()}"
        )
        return out
