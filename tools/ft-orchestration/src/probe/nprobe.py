from abc import ABC
from os import PathLike
from pathlib import Path
import tempfile
from typing import List, Optional
from src.common.tool_is_installed import assert_tool_is_installed
from src.config.common import InterfaceCfg
from src.probe.interface import ProbeInterface
from lbr_testsuite.executable import Executor, RemoteExecutor, LocalExecutor
from fabric import Connection
from src.probe.pidstat import PidStat
from src.probe.probe_target import ProbeTarget

SETTINGS_TO_ARGS: dict[str, str] = {
    "active_timeout": "-t",
    "inactive_timeout": "-d",
    "queue_timeout": "-l",
    "aggregation": "-p",
    "in_iface_idx": "-u",
    "out_iface_idx": "-Q",
    "vlanid_as_iface_idx": "--vlanid-as-iface-idx",
    "discard_unknown_flows": "--discard-unknown-flows",
    "ndpi_protocols": "-O",
    "ndpi_categories_dir": "--ndpi-categories-dir",
    "flow_delay": "-e",
    "count_delay": "-B",
    "min_flow_size": "-z",
    "max_num_flows": "-M",
    "min_num_flows": "-m",
    "netflow_engine": "-E",
    "sender_address": "-q",
    "flow_template": "-T",
    "flow_template_id": "-U",
    "flow_version": "-V",
    "fows_intra_templ": "-o",
    "black_list": "--black-list",
    "biflows_export_policy": "-N",
}


class NProbeSettings(ABC):
    active_timeout: int = 300
    inactive_timeout: int = 30
    queue_timeout: int = 15

    aggregation: Optional[str] = None
    in_iface_idx: Optional[int] = None
    out_iface_idx: Optional[int] = None
    vlanid_as_iface_idx: Optional[str] = None
    discard_unknown_flows: Optional[int] = None
    ndpi_protocols: Optional[List[str]] = None
    ndpi_categories_dir: Optional[PathLike] = None
    flow_delay: Optional[int] = None
    count_delay: Optional[int] = None
    min_flow_size: Optional[str] = None
    max_num_flows: Optional[int] = None
    min_num_flows: Optional[int] = None
    netflow_engine: Optional[str] = None
    sender_address: Optional[str] = None
    flow_template: Optional[str] = None
    flow_template_id: Optional[int] = None
    flow_version: Optional[int] = 10  # for IPFIX
    fows_intra_templ: Optional[int] = None
    black_list: Optional[str] = None
    biflows_export_policy: Optional[int] = None


class NProbe(ProbeInterface):
    host_statistics = None

    def __init__(
        self,
        executor: Executor,
        target: ProbeTarget,
        protocols: List[str],
        interfaces: List[InterfaceCfg],
        verbose: bool = False,
        settings: NProbeSettings = None,
        sudo: bool = False,
    ):
        self._executor = executor
        if isinstance(executor, RemoteExecutor):
            connection: Connection = executor.get_connection()
            stats_executor = RemoteExecutor(
                executor.get_host(), **connection.connect_kwargs
            )
        else:
            stats_executor = LocalExecutor()

        self._process = None
        self._sudo = sudo
        self._ifc_names = ",".join([ifc.name for ifc in interfaces])
        self._verbose = verbose
        self._enabled_plugins = []
        self._last_run_stats = None
        self._timeouts = (settings.active_timeout, settings.inactive_timeout)

        assert_tool_is_installed("nprobe", executor)
        self._cmd = self._prepare_cmd(target, protocols, settings)
        self.host_statistics = PidStat(stats_executor, self._cmd.split(" ", 1)[0])

        self._local_workdir = tempfile.mkdtemp()
        self._log_file = Path(self._local_workdir, "nprobe.log")

    def _prepare_cmd(
        self, target: ProbeTarget, protocols: List[str], settings: NProbeSettings
    ) -> str:
        cmd = "nprobe"
        settings.ndpi_protocols = list(set(settings.ndpi_protocols) & set(protocols))
        args: List[str] = [
            cmd,
            "-n",
            f"{target.protocol}://{target.host}:{target.port}",
        ]

        for setting, arg in SETTINGS_TO_ARGS.items():
            if hasattr(settings, setting):
                value = getattr(settings, setting)
                if value:
                    args.append(arg)
                    if isinstance(value, List):
                        args.append(f'"{",".join(value)}"')
                    args.append(value)

        return " ".join(args)

    def start(self):
        """Start the probe."""
        # TODO: Implement
        raise NotImplementedError

    def supported_fields(self):
        """Get list of IPFIX fields the probe may export in its current configuration."""
        # TODO: Implement
        raise NotImplementedError

    def get_special_fields(self):
        """Return dictionary of exported fields that need special evaluation."""
        # TODO: Implement
        raise NotImplementedError

    def stop(self):
        """Stop the probe."""
        # TODO: Implement
        raise NotImplementedError

    def cleanup(self):
        """Clean any artifacts which were created by the connector or the active probe itself."""
        # TODO: Implement
        raise NotImplementedError

    def download_logs(self, directory: str):
        """Download logs to given directory.

        Parameters
        ----------
        directory : str
            Path to a local directory where logs should be stored.
        """
        # TODO: Implement
        raise NotImplementedError

    def get_timeouts(self) -> tuple[int, int]:
        """Get active and inactive timeouts of the probe (in seconds).

        Returns
        -------
        tuple
            active_timeout, inactive_timeout
        """
        # TODO: Implement
        raise NotImplementedError

    def set_prefilter(self, ip_ranges: list[str]) -> None:
        """Set probe input filter. Probe will drop all the traffic except specified IP ranges.

        Parameters
        ----------
        ip_ranges : list[str]
            IP ranges passed by the filter.
        """
        # TODO: Implement
        raise NotImplementedError
