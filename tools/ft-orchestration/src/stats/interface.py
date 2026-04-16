from abc import ABC, abstractmethod
from os import PathLike
from lbr_testsuite.executable import Executor


class HostStats(ABC):
    """
    Abstract class defining an interface for a program that reads statistics from a host.
    """

    @abstractmethod
    def __init__(self, executor: Executor, watch_cmd: str):
        """
        Constructor.

        Args:
            executor (Executor): Executor object.
            watch_cmd (str): Program name to watch statistics for.
        """
        pass

    @property
    @abstractmethod
    def cpus(self) -> int:
        """
        Number of CPUs.
        """
        pass

    @property
    @abstractmethod
    def total_ram(self) -> int:
        """
        Size of RAM in kB.
        """
        pass

    @property
    @abstractmethod
    def local_file(self) -> PathLike:
        """
        Path to locally stored CSV file.
        """
        pass

    @abstractmethod
    def start(self):
        """
        Start collecting statistics.
        """
        pass

    @abstractmethod
    def stop(self):
        """
        Stop collecting statistics.
        """
        pass

    @abstractmethod
    def cleanup(self):
        """
        Remove temporary files.
        """
        pass

    @abstractmethod
    def get_csv(self, output_dir: PathLike):
        """
        Download the CSV file containing statistics to the output directory.

        Args:
            output_dir (PathLike): Path where to copy CSV to.
        """
        pass
