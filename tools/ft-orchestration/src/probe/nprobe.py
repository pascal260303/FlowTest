from abc import ABC
from dataclasses import dataclass, field
import ipaddress
import logging
from os import PathLike
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import List, Optional
from src.common.required_field import required_field
from src.common.tool_is_installed import assert_tool_is_installed
from src.common.typed_dataclass import typed_dataclass
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
    "flow_version": "-V",
    "active_timeout": "-t",
    "inactive_timeout": "-d",
    "queue_timeout": "-l",
    "sample_rate": "-S",
    "hash_size": "-w",
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
    "fows_intra_templ": "-o",
    "black_list": "--black-list",
    "biflows_export_policy": "-N",
}

BASIC_TEMPLATE = r'"%FLOW_START_MILLISECONDS %FLOW_END_MILLISECONDS %PROTOCOL %IPV4_SRC_ADDR %IPV6_SRC_ADDR %IPV4_DST_ADDR %IPV6_DST_ADDR %L4_SRC_PORT %L4_DST_PORT %IN_PKTS %IN_BYTES"'


@typed_dataclass
@dataclass
class NProbeSettings(ABC):
    # general options
    interfaces: List[str] = required_field()
    active_timeout: int = 300
    inactive_timeout: int = 30
    queue_timeout: int = 15
    sample_rate: str = "1:1:1"
    hash_size: int = 131072

    # Exporter options
    aggregation: Optional[str] = "0.0/1/1/1/0/0/0/0/0/0" # set the flow key to protocol, IP, port
    in_iface_idx: Optional[int] = None
    out_iface_idx: Optional[int] = None
    vlanid_as_iface_idx: Optional[str] = None
    discard_unknown_flows: Optional[int] = None
    ndpi_protocols: Optional[List[str]] = field(default_factory=lambda: [])
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

    # zero copy driver options
    rss_queues: int = 1


class NProbe(ProbeInterface):
    host_statistics = None

    def __init__(
        self,
        executor: Executor,
        target: ProbeTarget,
        protocols: List[str],
        interfaces: List[InterfaceCfg],
        verbose: bool = False,
        mtu: int = 2048,
        sudo: bool = False,
        **kwargs: dict,
    ):
        interfaces_names = [ifc.name for ifc in interfaces]
        self._interfaces = interfaces_names
        self._zero_copy = any(ifc.startswith("zc:") for ifc in self._interfaces)
        settings: NProbeSettings = NProbeSettings(interfaces=interfaces_names, **kwargs)
        self._executor = executor
        if isinstance(executor, RemoteExecutor):
            connection: Connection = executor.get_connection()
            self._fallback_executor = RemoteExecutor(
                executor.get_host(), **connection.connect_kwargs
            )
            stats_executor = RemoteExecutor(
                executor.get_host(), **connection.connect_kwargs
            )
        else:
            self._fallback_executor = LocalExecutor()
            stats_executor = LocalExecutor()

        self._process = None
        self._sudo = sudo
        self._verbose = verbose
        self._enabled_plugins = []
        self._last_run_stats = None
        self._timeouts = (settings.active_timeout, settings.inactive_timeout)
        self._settings: NProbeSettings = settings
        self._mtu = mtu
        self._target = target
        self._protocols = protocols

        assert_tool_is_installed("nprobe", executor)
        if self._zero_copy:
            assert_tool_is_installed("pf_ringcfg", executor)
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
        ]

        for interface in self._interfaces:
            args.extend(["-i", interface])

        for setting, arg in SETTINGS_TO_ARGS.items():
            if hasattr(settings, setting):
                value = getattr(settings, setting)
                if value:
                    args.append(arg)
                    if isinstance(value, List):
                        args.append(f'"{",".join(value)}"')
                    args.append(str(value))

        return " ".join(args)

    def _switch_to_zc(self, interface_name: str):
        driver, _ = Tool(
            f"pf_ringcfg --list-interfaces | grep {interface_name} | grep -o 'Driver: [^ ]*'",
            executor=self._executor,
            sudo=self._sudo,
            failure_verbosity="silent",
        ).run()
        driver = driver.split(" ")[1].strip()
        if driver.endswith("_zc"):
            driver = driver[:-3]
            Tool(
                f"pf_ringcfg --configure-driver {driver}",
                executor=self._executor,
                sudo=self._sudo,
            ).run()
        Tool(
            f"pf_ringcfg --configure-driver {driver} --rss-queues {self._settings.rss_queues}",
            executor=self._executor,
            sudo=self._sudo,
        ).run()

    def _switch_back_zc(self, interface_name: str):
        driver, _ = Tool(
            f"pf_ringcfg --list-interfaces | grep {interface_name} | grep -o 'Driver: [^ ]*'",
            executor=self._executor,
            sudo=self._sudo,
            failure_verbosity="silent",
        ).run()
        driver = driver.split(" ")[1]
        if not driver.endswith("_zc"):
            return
        driver = driver[:-3]
        Tool(
            f"pf_ringcfg --configure-driver {driver}    ",
            executor=self._executor,
            sudo=self._sudo,
        ).run()

    def _before_start(self):
        for ifc in self._interfaces:
            name = ifc.split(":", 1)[-1]
            Tool(
                f"ip link set dev {name} up", executor=self._executor, sudo=self._sudo
            ).run()
            Tool(
                f"ip link set dev {name} mtu {self._mtu}",
                executor=self._executor,
                sudo=self._sudo,
            ).run()
            if ifc.startswith("zc:"):
                self._switch_to_zc(name)

    def start(self):
        """Start the probe."""
        logging.getLogger().info(
            "Starting nprobe exporter on %s.", ",".join(self._interfaces)
        )
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
                ",".join(self._interfaces),
                return_code,
                err,
            )
            raise ProbeException("nprobe startup error")

    def _after_stop(self):
        for interface in self._interfaces:
            if interface.startswith("zc:"):
                self._switch_back_zc(interface.split(":")[-1])

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
        self._after_stop()

    def supported_fields(self):
        """Get list of IPFIX fields the probe may export in its current configuration."""
        output, _ = Tool(
            r"nprobe -H | awk '/NetFlow v9\/IPFIX format \[-T\]/ {p=1; next} /Major protocol \(%L7_PROTO\)/ {p=0} p' | grep '^\['",
            executor=self._executor,
        ).run()
        lines = output.split("\n")
        fields = [re.findall(r"%[^ ]+", line)[1] for line in lines if line]
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

        # Wait till nprobe finishes
        Tool(
            f"while pidof {self._cmd.split(' ', 1)[0]} > /dev/null; do :; done",
            executor=self._executor,
            sudo=self._sudo,
            failure_verbosity="silent",
        ).run()

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
        self._cmd = self._prepare_cmd(self._target, self._protocols, self._settings)
