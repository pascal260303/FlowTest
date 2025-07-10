from abc import ABC
import ipaddress
import logging
from os import PathLike
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import List, Optional
from src.common.tool_is_installed import assert_tool_is_installed
from src.config.common import InterfaceCfg
from src.probe.interface import ProbeException, ProbeInterface
from lbr_testsuite.executable import (
    Executor,
    RemoteExecutor,
    LocalExecutor,
    Tool,
    Daemon,
    ExecutableProcessError,
)
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

BASIC_TEMPLATE = r'"%flowStartMilliseconds,%flowEndMilliseconds,%protocolIdentifier,%sourceIPv4Address,%sourceIPv6Address,%destinationIPv4Address,%destinationIPv6Address,%sourceTransportPort,%destinationTransportPort,%packetDeltaCount,%octetDeltaCount"'


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
    flow_template: Optional[str] = BASIC_TEMPLATE
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
        mtu: int = 2048,
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
        self._settings = settings
        self._mtu = mtu

        assert_tool_is_installed("nprobe", executor)
        self._cmd = self._prepare_cmd(target, protocols, settings)
        self.host_statistics = PidStat(stats_executor, self._cmd.split(" ", 1)[0])

        self._local_workdir = tempfile.mkdtemp()
        self._log_file = Path(self._local_workdir, "nprobe.log")

    def _prepare_cmd(
        self, target: ProbeTarget, protocols: List[str], settings: NProbeSettings
    ) -> str:
        settings.ndpi_protocols = list(set(settings.ndpi_protocols) & set(protocols))
        cmd = "nprobe"
        args: List[str] = [
            cmd,
            "-n",
            f"{target.protocol}://{target.host}:{target.port}",
            "-i",
            self._ifc_names,
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

    def _before_start(self):
        for ifc in self._ifc_names.split(","):
            Tool(
                f"ip link set dev {ifc} up", executor=self._executor, sudo=self._sudo
            ).run()
            Tool(
                f"ip link set dev {ifc} mtu {self._mtu}",
                executor=self._executor,
                sudo=self._sudo,
            ).run()

    def start(self):
        """Start the probe."""
        logging.getLogger().info("Starting nprobe exporter on %s.", self._ifc_names)
        self._last_run_stats = None

        self._before_start()

        # check and stop running nprobe instance
        check_running_cmd = "pidof 'nprobe'"
        running_processes = Tool(
            check_running_cmd, executor=self._executor, failure_verbosity="silent"
        ).run()[0]
        if len(running_processes) > 0:
            running_pid = int(running_processes.split()[0])
            self._stop_process(running_pid)
            time.sleep(2)

        self.host_statistics.start()

        self._process = Daemon(self._cmd, executor=self._executor, sudo=self._sudo)
        # stderr is implicitly redirected to stdout
        self._process.set_outputs(self._log_file)
        self._process.start()
        time.sleep(1)

        if not self._process.is_running():
            res = self._process.stop()
            return_code = self._process.returncode()
            self._process = None

            # stderr is redirected to stdout
            err = res[0]
            logging.getLogger().error(
                "Unable to start probe on %s. nprobe return code: %d, error: %s",
                self._ifc_names,
                return_code,
                err,
            )
            raise ProbeException("nprobe startup error")

    def _stop_process(self, pid):
        """Stop exporter process"""

        Tool(
            f"kill -2 {pid}",
            executor=self._executor,
            failure_verbosity="silent",
            sudo=True,
        ).run()
        ps_ec = Tool(
            f"ps -p {pid}", executor=self._executor, failure_verbosity="silent"
        )
        for _ in range(5):
            ps_ec.run()
            if ps_ec.returncode() == 1:
                return
            time.sleep(1)
        logging.getLogger().warning(
            "Unable to stop exporter process with SIGINT, using SIGKILL."
        )
        Tool(
            f"kill -9 {pid}",
            executor=self._executor,
            failure_verbosity="silent",
            sudo=True,
        ).run()

    def supported_fields(self):
        """Get list of IPFIX fields the probe may export in its current configuration."""
        output, _ = Tool(
            r"nprobe -H | awk '/NetFlow v9\/IPFIX format \[-T\]/ {p=1; next} /Major protocol \(%L7_PROTO\)/ {p=0} p' | grep '^\['",
            executor=self._executor,
        ).run()
        lines = output.split("\n")
        fields = [re.findall(r"%[^ ]+ ", line)[-1].strip() for line in lines if line]
        return fields

    def get_special_fields(self):
        """Return dictionary of exported fields that need special evaluation."""
        basic_fields = set(BASIC_TEMPLATE.replace('"', "").split(","))
        used_fields = set(self._settings.flow_template.replace('"', "").split(","))
        special_fields = {field: None for field in (used_fields - basic_fields)}
        return special_fields

    def stop(self):
        """Stop the probe."""
        # if process not running, method has no effect
        if self._process is None:
            return

        logging.getLogger().info("Stopping nprobe exporter.")

        command = self._cmd.split(" ", 1)[0]
        Tool(
            f"killall {command})",
            executor=self._fallback_executor,
            failure_verbosity="silent",
        ).run()

        stdout = []
        try:
            stdout, _ = self._process.stop()
        except ExecutableProcessError:
            pass

        if self._process.returncode() > 0:
            # stderr is redirected to stdout
            # Since stdout could be filled with normal output, print only last 1 line#
            err = stdout[-1]
            logging.getLogger().error(
                "nprobe runtime error: %s, error: %s",
                self._process.returncode(),
                err,
            )
            self._last_run_stats = None
            raise ProbeException("nprobe runtime error")

        self._process = None
        self.host_statistics.stop()

    def cleanup(self):
        """Clean any artifacts which were created by the connector or the active probe itself."""
        Tool(f"rm -rf {self._local_workdir}").run()
        self.host_statistics.cleanup()

    def download_logs(self, directory: str):
        """Download logs to given directory.

        Parameters
        ----------
        directory : str
            Path to a local directory where logs should be stored.
        """
        try:
            shutil.copy(self._log_file, directory)
            self.host_statistics.get_csv(directory)
        except PermissionError as err:
            logging.getLogger().warning("Cannot download ipfixprobe log, %s", err)

    def get_timeouts(self) -> tuple[int, int]:
        """Get active and inactive timeouts of the probe (in seconds).

        Returns
        -------
        tuple
            active_timeout, inactive_timeout
        """
        return self._timeouts

    def set_prefilter(self, ip_ranges: list[str]) -> None:
        """Set probe input filter. Probe will drop all the traffic except specified IP ranges.

        Parameters
        ----------
        ip_ranges : list[str]
            IP ranges passed by the filter.
        """

        def compute_blacklist(whitelist, version=4):
            full_space = ipaddress.ip_network("0.0.0.0/0" if version == 4 else "::/0")
            blacklist = [full_space]

            for allowed in whitelist:
                new_blacklist = []
                for net in blacklist:
                    # Subtract the allowed network from the current blacklist network
                    new_blacklist.extend(net.address_exclude(allowed))
                blacklist = new_blacklist

            return blacklist

        ipv4_ranges = [
            net for net in ip_ranges if isinstance(net, ipaddress.IPv4Network)
        ]
        # no ipv6 support for --black-list
        # ipv6_range = [
        #    ip_network
        #    for ip_network in ip_ranges
        #    if isinstance(ip_network, ipaddress.IPv6Network)
        # ]
        blacklist = compute_blacklist(ipv4_ranges, 4)
        # no ipv6 support for --black-list
        # blacklist += compute_blacklist(ipv6_range, 6)

        self._settings.black_list = ",".join(str(net) for net in blacklist)
        self._cmd = self._prepare_cmd
