from abc import ABC, abstractmethod
import math
from os import PathLike
import os
from ..statistic_object import StatisticObject
import numpy as np


class Counter(StatisticObject, ABC):
    """
    Basic counter that tracks sum, sum of squares, minimum, maximum, and sample count for a variable.
    """

    _sum_power_one: np.float64
    """Sum of values counted by this counter
    """

    _sum_power_two: np.float64
    """Sum of square values counted by this counter
    """

    __min: np.float64

    __max: np.float64

    _observed_variable: str

    __counter_type: str

    __num_samples: np.uint64

    def __init__(
        self,
        variable: str,
        type: str = "counter type: base counter",
        has_negatives: bool = False,
    ) -> None:
        """
        Initialize a counter for a given variable.
        Args:
            variable: Name of the observed variable.
            type: Description of the counter type.
            has_negatives: If True, allow negative values for min.
        """
        self.__counter_type = type
        self._observed_variable = variable
        self._sum_power_one = 0
        self._sum_power_two = 0
        self.__min = np.inf
        self.__max = -np.inf
        self.__num_samples = 0
        self._has_negatives = has_negatives

    def get_counter_type(self):
        return self.__counter_type

    @abstractmethod
    def get_mean(self) -> np.float64:
        """
        Returns the mean of the observed variable.
        Returns:
            Mean value as np.float64.
        """
        pass

    @abstractmethod
    def get_variance(self) -> np.float64:
        """
        Returns the variance of the observed variable.
        Returns:
            Variance as np.float64.
        """
        pass

    def get_std_deviation(self) -> np.float64:
        """
        Returns the standard deviation of the observed variable.
        Returns:
            Standard deviation as np.float64.
        """
        return math.sqrt(max(self.get_variance(), 0))

    def get_cvar(self) -> np.float64:
        """
        Returns the coefficient of variation of the observed variable.
        Returns:
            Coefficient of variation as np.float64.
        """
        if self.get_mean() == 0:
            return 0 if self.get_std_deviation() == 0 else np.finfo(np.float64).max
        else:
            return self.get_std_deviation() / self.get_mean()

    def get_min(self) -> np.float64:
        """
        Returns the minimum value observed.
        Returns:
            Minimum value as np.float64.
        """
        return self.__min

    def get_max(self) -> np.float64:
        """
        Returns the maximum value observed.
        Returns:
            Maximum value as np.float64.
        """
        return self.__max

    def get_num_samples(self) -> np.uint64:
        """
        Returns the number of counted samples.
        Returns:
            Number of samples as np.uint64.
        """
        return self.__num_samples

    def get_sum_power_one(self) -> np.float64:
        """
        Returns the sum of all counted samples.
        Returns:
            Sum as np.float64.
        """
        return self._sum_power_one

    def increase_sum_power_one(self, value: np.float64) -> None:
        """
        Add the given value to the sum of counted samples.
        Args:
            value: Value to add.
        """
        self._sum_power_one += value

    def get_sum_power_two(self) -> np.float64:
        """
        Returns the sum of all counted samples squared.
        Returns:
            Sum of squares as np.float64.
        """
        return self._sum_power_two

    def increase_sum_power_two(self, value: np.float64) -> None:
        """
        Add the given value to the sum of counted samples squared.
        Args:
            value: Value to add.
        """
        self._sum_power_two += value

    def count(self, x: np.float64) -> None:
        """
        Count a new sample (set min/max and increment sample counter).
        Args:
            x: Value to count.
        """
        self.__min = min(self.__min, x)
        if not self._has_negatives:
            self.__min = max(0, self.__min)
        self.__max = max(self.__max, x)
        self.__num_samples += 1

    def report(self) -> str:
        """
        Output a string report of this counter.
        Returns:
            Report as string.
        """
        out: str = ""
        if self._observed_variable:
            out += f"observed metric: {self._observed_variable}\n"

        out += (
            f"\t{self.__counter_type}\n"
            + f"\tnumber of samples: {self.__num_samples}\n"
            + f"\tmean: {self.get_mean()}\n"
            + f"\tvariance: {self.get_variance()}\n"
            + f"\tstandard deviation: {self.get_std_deviation()}\n"
            + f"\tcoefficient of variation: {self.get_cvar()}\n"
            + f"\tminimum: {self.__min}\n"
            + f"\tmaximum: {self.__max}"
        )

        return out

    def csv_report(
        self,
        output_dir: PathLike,
        is_ref: bool = False,
        create_subdir: bool = True,
    ) -> None:
        """
        Write counter details to a CSV file.
        Args:
            output_dir: Output directory for CSV file.
            is_ref: If True, write to expected-counters folder.
            create_subdir: If True, create and use the counter or expected-counter dir
        """
        content: str = f"{self._observed_variable};{self.__num_samples};{self.get_mean()};{self.get_variance()};{self.get_std_deviation()};{self.get_cvar()};{self.get_min()};{self.get_max()}\n"
        labels: str = "#counter ; numSamples ; MEAN; VAR; STD; CVAR; MIN; MAX\n"
        if create_subdir:
            output_dir = os.path.join(
                output_dir, "expected-counters" if is_ref else "counters"
            )
        self._write_csv(
            output_dir,
            content,
            labels,
        )

    def _write_csv(
        self,
        output_dir: PathLike,
        content: str,
        labels: str,
    ) -> None:
        """
        Helper to write CSV content to file.
        Args:
            output_dir: Output directory.
            content: CSV content string.
            labels: CSV header string.
        """
        try:
            os.makedirs(output_dir, exist_ok=True)

            filename = os.path.join(output_dir, f"{self.__class__.__name__}.csv")
            file_exists = os.path.exists(filename)

            with open(filename, "a", encoding="utf-8") as csvwriter:
                if not file_exists:
                    content = labels + content
                csvwriter.write(content)

        except IOError as e:
            print(f"IOError while writing CSV: {e}")

    def reset(self) -> None:
        """
        Reset all statistics to initial state.
        """
        self._sum_power_one = 0
        self._sum_power_two = 0
        self.__min = np.inf
        self.__max = -np.inf
        self.__num_samples = 0
