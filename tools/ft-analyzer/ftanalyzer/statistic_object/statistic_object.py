from abc import ABC, abstractmethod
from os import PathLike


class StatisticObject(ABC):
    """Abstract Class for statistic objects such as Counters and Histograms."""

    @abstractmethod
    def count(self, x: float):
        """Count sample

        Args:
            x (float): counter value
        """
        pass

    @abstractmethod
    def report(self) -> str:
        """Report to console

        Returns:
            str: output in string format
        """
        pass

    @abstractmethod
    def csv_report(self, output_dir: PathLike, is_ref: bool = False):
        """Report to csv-file

        Args:
            output_dir (PathLike): filepath
        """
        pass

    @abstractmethod
    def reset(self):
        """Reset all internal data structures"""
        pass
