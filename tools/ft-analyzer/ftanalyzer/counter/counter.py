from abc import ABC, abstractmethod
import math
from os import PathLike
import os
from ..statistic_object import StatisticObject
import numpy as np


class Counter(StatisticObject, ABC):
    """Basic counter that counts: * sum power two * sum power one * minimum * maximum"""

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
    ):
        """Constructor

        Args:
            variable (str): the observed variable
            type (_type_, optional): the type of counter. Defaults to "counter type: base counter".
        """
        self.__counter_type = type
        self._observed_variable = variable
        self._sum_power_one = 0
        self._sum_power_two = 0
        self.__min = np.inf
        self.__max = -np.inf
        self.__num_samples = 0
        self._has_negatives = has_negatives

    @abstractmethod
    def get_mean(self) -> np.float64:
        """Returns the mean of the observed variable

        Returns:
            np.float64: the mean
        """
        pass

    @abstractmethod
    def get_variance(self) -> np.float64:
        """Returns the variance of the observed variable

        Returns:
            np.float64: the variance
        """
        pass

    def get_std_deviation(self) -> np.float64:
        """Returns the standard deviation of the observed variable

        Returns:
            np.float64: the standard deviation
        """
        return math.sqrt(self.get_variance())

    def get_cvar(self) -> np.float64:
        """Returns the co-variance of the observed variable

        Returns:
            np.float64: the co-variance
        """
        if self.get_mean() == 0:
            return 0 if self.get_std_deviation() == 0 else np.finfo(np.float64).max
        else:
            return self.get_std_deviation() / self.get_mean()

    def get_min(self) -> np.float64:
        """Returns the minimum of the observed variable

        Returns:
            np.float64: the minimum
        """
        return self.__min

    def get_max(self) -> np.float64:
        """Returns the maximum of the observed variable

        Returns:
            np.float64: the maximum
        """
        return self.__max

    def get_num_samples(self) -> np.uint64:
        """Returns the number of counted samples

        Returns:
            np.uint64: the number of samples
        """
        return self.__num_samples

    def get_sum_power_one(self) -> np.float64:
        """Returns the sum of all counted samples

        Returns:
            np.float64: the sum of all samples
        """
        return self._sum_power_one

    def increase_sum_power_one(self, value: np.float64):
        """Adds the given value to the sum of counted samples

        Args:
            value (np.float64): the value to add
        """
        self._sum_power_one += value

    def get_sum_power_two(self) -> np.float64:
        """Returns the sum of all counted samples power two

        Returns:
            np.float64: the sum of all samples power two
        """
        return self._sum_power_two

    def increase_sum_power_two(self, value: np.float64):
        """Adds the given value to the sum of counted samples

        Args:
            value (np.float64): the value to add
        """
        self._sum_power_two += value

    def count(self, x: np.float64):
        """Counts a new sample (set min/max and increment sample counter)

        Args:
            x (np.float64): the value to count
        """
        self.__min = min(self.__min, x)
        if not self._has_negatives:
            self.__min = max(0, self.__min)
        self.__max = max(self.__max, x)
        self.__num_samples += 1

    def report(self) -> str:
        """Outputs the report of this counter to the command line

        Returns:
            str: output as string
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

    def csv_report(self, output_dir: PathLike):
        """Write Counter details to csv-file

        Args:
            output_dir (PathLike): _description_
        """
        content: str = f"{self._observed_variable};{self.__num_samples};{self.get_mean()};{self.get_variance()};{self.get_std_deviation()};{self.get_cvar()};{self.get_min()};{self.get_max()}\n"
        labels: str = "#counter ; numSamples ; MEAN; VAR; STD; CVAR; MIN; MAX\n"
        self._write_csv(output_dir, content, labels)

    def _write_csv(self, output_dir: PathLike, content: str, labels: str):
        try:
            dest = os.path.join(output_dir, "counters")
            os.makedirs(dest, exist_ok=True)

            filename = os.path.join(dest, f"{self.__class__.__name__}.csv")
            file_exists = os.path.exists(filename)

            with open(filename, "a", encoding="utf-8") as csvwriter:
                if not file_exists:
                    content = labels + content
                csvwriter.write(content)

        except IOError as e:
            print(f"IOError while writing CSV: {e}")

    def reset(self):
        self._sum_power_one = 0
        self._sum_power_two = 0
        self.__min = np.inf
        self.__max = -np.inf
        self.__num_samples = 0
