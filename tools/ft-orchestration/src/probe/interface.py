"""
Author(s):  Vojtech Pecen <vojtech.pecen@progress.com>
            Michal Panek <michal.panek@progress.com>

Copyright: (C) 2022 Flowmon Networks a.s.
SPDX-License-Identifier: BSD-3-Clause

Contains interface definition which all probes must implement.
"""

from abc import ABC, abstractmethod
from os import PathLike
from lbr_testsuite.executable import Executor


class ProbeException(Exception):
    """Basic exception raised by the probe implementations"""


class ProbeInterface(ABC):
    """Abstract class defining common interface for all probes"""

    @abstractmethod
    def __init__(
        self,
        executor,
        target,
        protocols,
        interfaces,
        *,
        verbose,
        mtu,
        active_timeout,
        inactive_timeout,
        **kwargs,
    ):
        """Initialize the local or remote probe interface as object

        Parameters
        ----------

        executor : lbr_testsuite.executable.Executor
            Initialized executor object with the deployed probe.

        target : src.probe.probe_target
            Target object for the exporter/probe

        protocols : list
            List of the networking protocols which the probe should parse and export.

        interfaces : list(InterfaceCfg)
            Network interfaces where the exporting process should be initiated.

        verbose : bool, optional
            Increase verbosity of probe logs.

        mtu : int, optional
            The maximum transmission unit to be set at the probe input.

        active_timeout : int, optional
            Maximum duration of an ongoing flow before the probe exports it (in seconds).

        inactive_timeout : int, optional
            Maximum duration for which a flow is kept in the probe if no new data updates it (in seconds).

        kwargs : dict
            Additional startup arguments for specific probe variants.

        Raises
        ------
        ProbeException
            Unable to initialize the probe.
        """
        raise NotImplementedError

    @abstractmethod
    def start(self):
        """Start the probe."""
        raise NotImplementedError

    @abstractmethod
    def supported_fields(self):
        """Get list of IPFIX fields the probe may export in its current configuration."""
        raise NotImplementedError

    @abstractmethod
    def get_special_fields(self):
        """Return dictionary of exported fields that need special evaluation."""
        raise NotImplementedError

    @abstractmethod
    def stop(self):
        """Stop the probe."""
        raise NotImplementedError

    @abstractmethod
    def cleanup(self):
        """Clean any artifacts which were created by the connector or the active probe itself."""
        raise NotImplementedError

    @abstractmethod
    def download_logs(self, directory: str):
        """Download logs to given directory.

        Parameters
        ----------
        directory : str
            Path to a local directory where logs should be stored.
        """
        raise NotImplementedError

    @abstractmethod
    def get_timeouts(self) -> tuple[int, int]:
        """Get active and inactive timeouts of the probe (in seconds).

        Returns
        -------
        tuple
            active_timeout, inactive_timeout
        """

        raise NotImplementedError

    def set_prefilter(self, ip_ranges: list[str]) -> None:
        """Set probe input filter. Probe will drop all the traffic except specified IP ranges.

        Parameters
        ----------
        ip_ranges : list[str]
            IP ranges passed by the filter.
        """

        raise NotImplementedError


class HostStats(ABC):
    """Abstract class defining an Interface for a programm that reads statistics from a host"""

    @abstractmethod
    def __init__(self, executor: Executor, watch_cmd: str):
        """Constructor

        Args:
            executor (_type_): _description_
            watch_cmd (str): the program name to what statistics for
        """
        pass
    
    @property
    @abstractmethod
    def cpus(self) -> int:
        """number of cpus
        """
        pass
    
    @property
    @abstractmethod
    def total_ram(self) -> int:
        """size of ram in kB
        """
        pass
    
    @abstractmethod
    def start(self):
        """Start collecting statistics
        """
        pass
    
    @abstractmethod
    def stop(self):
        """Stop collecting statistics
        """
        pass
    
    @abstractmethod
    def cleanup(self):
        """Remove temporary files
        """
        pass
    
    @abstractmethod
    def get_csv(self, output_dir: PathLike):
        """Download the csv file containing statistics to the output_dir

        Args:
            output_dir (PathLike): path where to copy csv to
        """
        pass
