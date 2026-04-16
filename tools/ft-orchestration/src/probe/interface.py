"""
Author(s):  Vojtech Pecen <vojtech.pecen@progress.com>
            Michal Panek <michal.panek@progress.com>

Copyright: (C) 2022 Flowmon Networks a.s.
SPDX-License-Identifier: BSD-3-Clause

Contains interface definition which all probes must implement.
"""

from abc import ABC, abstractmethod
from src.stats.interface import HostStats


class ProbeException(Exception):
    """
    Basic exception raised by probe implementations.
    """


class ProbeInterface(ABC):
    """
    Abstract class defining common interface for all probes.
    """

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
        cache_size,
        **kwargs,
    ):
        """
        Initialize the local or remote probe interface as an object.

        Args:
            executor (Executor): Initialized executor object with the deployed probe.
            target: Target object for the exporter/probe.
            protocols (list): List of networking protocols to parse and export.
            interfaces (list[InterfaceCfg]): Network interfaces for the exporting process.
            verbose (bool, optional): Increase verbosity of probe logs.
            mtu (int, optional): Maximum transmission unit for the probe input.
            active_timeout (int, optional): Maximum duration of an ongoing flow before export (seconds).
            inactive_timeout (int, optional): Maximum duration for which a flow is kept if no new data updates it (seconds).
            cache_size: Additional cache size argument.
            **kwargs: Additional startup arguments for specific probe variants.

        Raises:
            ProbeException: Unable to initialize the probe.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def host_statistics(self) -> HostStats:
        """
        Class to read statistics from the host.
        """
        pass

    @abstractmethod
    def start(self):
        """
        Start the probe.
        """
        raise NotImplementedError

    @abstractmethod
    def supported_fields(self):
        """
        Get list of IPFIX fields the probe may export in its current configuration.
        """
        raise NotImplementedError

    @abstractmethod
    def get_special_fields(self):
        """
        Return dictionary of exported fields that need special evaluation.
        """
        raise NotImplementedError

    @abstractmethod
    def stop(self):
        """
        Stop the probe.
        """
        raise NotImplementedError

    @abstractmethod
    def cleanup(self):
        """
        Clean any artifacts created by the connector or the active probe itself.
        """
        raise NotImplementedError

    @abstractmethod
    def download_logs(self, directory: str):
        """
        Download logs to the given directory.

        Args:
            directory (str): Path to a local directory where logs should be stored.
        """
        raise NotImplementedError

    @abstractmethod
    def get_timeouts(self) -> tuple[int, int]:
        """
        Get active and inactive timeouts of the probe (in seconds).

        Returns:
            tuple: active_timeout, inactive_timeout

        """
        raise NotImplementedError
        raise NotImplementedError

    def set_prefilter(self, ip_ranges: list[str]) -> None:
        """
        Set probe input filter. Probe will drop all traffic except specified IP ranges.

        Args:
            ip_ranges (list[str]): IP ranges passed by the filter.
        """
        raise NotImplementedError
