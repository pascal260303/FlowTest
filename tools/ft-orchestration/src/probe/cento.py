from abc import ABC
from dataclasses import dataclass, field
import logging
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
from src.probe.mpstat import MpStat
from src.probe.probe_target import ProbeTarget

SETTINGS_TO_ARGS: dict[str, str] = {
    "active_timeout": "-t",
    "inactive_timeout": "-d",
    "sample_rate": "--sample-rate",
    "hash_size": "-w",
    "max_hash_size": "-W",
    "ndpi_protocols": "-O",
    "flow_delay": "--flow-delay",
    "count_delay": "--count-delay",
    "flow_template": "--template",
    "processing_cores": "-g",
    "exporting_cores": "-G",
}

BOOL_ARGS: dict[str, str] = {
    "flow_offload": "--flow-offload",
    "zc": "-Z",
    "verbose": "--verbose",
    "active_poll": "-a",
    "tunnel": "--tunnel",
    "skip_fragments": "--skip-fragments",
    "uniflows": "--uniflows",
    "send_dont_wait": "--send-dont-wait",
    "hw_timestamp": "--hw-timestamp",
}

BASIC_TEMPLATE = r'"%FLOW_START_MILLISECONDS %FLOW_END_MILLISECONDS %PROTOCOL %IPV4_SRC_ADDR %IPV6_SRC_ADDR %IPV4_DST_ADDR %IPV6_DST_ADDR %L4_SRC_PORT %L4_DST_PORT %IN_PKTS %IN_BYTES"'


@typed_dataclass
@dataclass
class CentoSettings(ABC):
    """
    These settings can be set in probes.yml under `connector:`.
    Example:
        connector:
            sample_rate: "1:1"
    For possible values see `cento --help`.
    If unclear which setting affects which arg, see `SETTINGS_TO_ARGS` above.
    Settings not in that dict are ignored.
    """

    # general options
    interfaces: List[str] = required_field()
    active_timeout: int = 300
    inactive_timeout: int = 30
    sample_rate: str = "1:1"
    hash_size: int = 512000
    max_hash_size: int = 1024000

    # Exporter options
    ndpi_protocols: Optional[List[str]] = field(default_factory=lambda: [])
    flow_delay: Optional[int] = None
    count_delay: Optional[int] = None
    flow_template: Optional[str] = BASIC_TEMPLATE

    # boolean flags
    flow_offload: Optional[bool] = False
    zc: Optional[bool] = False
    verbose: Optional[bool] = False
    active_poll: Optional[bool] = False
    tunnel: Optional[bool] = False
    skip_fragments: Optional[bool] = False
    uniflows: bool = True
    send_dont_wait: Optional[bool] = False
    hw_timestamp: Optional[bool] = False

    # multicore settings
    processing_cores: Optional[str] = None
    exporting_cores: Optional[str] = None

    rss_queues: Optional[int] = 1


class Cento(ProbeInterface):
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
        cache_size=None,
        **kwargs: dict,
    ):
        interfaces_names = [ifc.name for ifc in interfaces]
        self._interfaces = interfaces_names
        self._zero_copy = any(ifc.startswith("zc:") for ifc in self._interfaces)

        if cache_size:
            kwargs["hash_size"] = min(
                2**cache_size, kwargs.get("hash_size", float("inf"))
            )
            kwargs["max_hash_size"] = 2**cache_size

        settings: CentoSettings = CentoSettings(
            interfaces=interfaces_names,
            verbose=verbose,
            ndpi_protocols=protocols,
            **kwargs,
        )
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
        self._timeouts = (settings.active_timeout, settings.inactive_timeout)
        self._settings: CentoSettings = settings
        self._mtu = mtu
        self._target = target

        assert_tool_is_installed("cento", executor)
        if self._zero_copy:
            assert_tool_is_installed("pf_ringcfg", executor)
        self._cmd = self._prepare_cmd(target, protocols, settings)
        self.host_statistics = MpStat(stats_executor, self._cmd.split(" ", 1)[0])

        self._local_workdir = tempfile.mkdtemp()
        self._log_file = Path(self._local_workdir, "cento.log")

    def _prepare_cmd(
        self, target: ProbeTarget, protocols: List[str], settings: CentoSettings
    ) -> str:
        settings.ndpi_protocols = list(set(settings.ndpi_protocols) & set(protocols))
        cmd = "cento"
        args: List[str] = [
            cmd,
            "-I",
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

        for setting, arg in BOOL_ARGS.items():
            if hasattr(settings, setting):
                value = getattr(settings, setting)
                if value:
                    args.append(arg)

        return " ".join(args)

    def _switch_to_zc(self, interface_name: str):
        driver, _ = Tool(
            f"pf_ringcfg --list-interfaces | grep {interface_name} | grep -o 'Driver: [^ ]*'",
            executor=self._executor,
            sudo=self._sudo,
            failure_verbosity="silent",
        ).run()
        if len(driver.split(" ")) < 2:
            return

        driver = driver.split(" ")[1].strip()
        if not driver.endswith("_zc"):
            Tool(
                f"pf_ringcfg --configure-driver {driver} --rss-queues 0",
                executor=self._executor,
                sudo=self._sudo,
            ).run()
            time.sleep(5)

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

    def _set_rss_queues(self, interface_name):
        Tool(
            f"ethtool --set-channels {interface_name} combined {self._settings.rss_queues}",
            executor=self._executor,
            sudo=self._sudo,
        ).run()

    def _before_start(self):
        interface_names = {name.split("@")[0] for name in self._interfaces}
        for ifc in interface_names:
            name = ifc.split(":", 1)[-1]
            Tool(
                f"ip link set {name} up", executor=self._executor, sudo=self._sudo
            ).run()
            Tool(
                f"ip link set {name} mtu {self._mtu}",
                executor=self._executor,
                sudo=self._sudo,
            ).run()
            Tool(
                f"ethtool -K {name} gro off gso off tso off",
                executor=self._executor,
                sudo=self._sudo,
            ).run()
            if ifc.startswith("zc:"):
                self._switch_to_zc(name)
            self._set_rss_queues(name)

    def start(self):
        """
        Start the probe.
        """
        logging.getLogger().info(
            "Starting cento exporter on %s.", ",".join(self._interfaces)
        )

        # check and stop running cento instance
        check_running_cmd = "pidof 'cento'"
        running_processes = Tool(
            check_running_cmd, executor=self._executor, failure_verbosity="silent"
        ).run()[0]
        if len(running_processes) > 0:
            pids = running_processes.split()
            for pid in pids:
                if not pid:
                    continue
                running_pid = int(pid)
                self._stop_process(running_pid)
                time.sleep(2)

        self._before_start()

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
                "Unable to start probe on %s. cento return code: %d, error: %s",
                ",".join(self._interfaces),
                return_code,
                err,
            )
            raise ProbeException("cento startup error")

        self.host_statistics.start()

    def _after_stop(self):
        pass

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
        """
        Get list of IPFIX fields the probe may export in its current configuration.
        """
        output, _ = Tool(
            r"cento --help | awk '/Supported template elements \(\-\-template\):/ {p=1} p' | grep '^ %'",
            executor=self._executor,
        ).run()
        lines = output.split("\n")
        fields = [re.findall(r"%[^ ]+", line)[0] for line in lines if line]
        return fields

    def get_special_fields(self):
        """
        Return dictionary of exported fields that need special evaluation.
        """
        basic_fields = set(BASIC_TEMPLATE.replace('"', "").split(","))
        used_fields = set(self._settings.flow_template.replace('"', "").split(","))
        special_fields = {field: None for field in (used_fields - basic_fields)}
        return special_fields

    def stop(self):
        """
        Stop the probe.
        """
        # if process not running, method has no effect
        if self._process is None:
            return

        logging.getLogger().info("Stopping cento exporter.")

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
                "cento runtime error: %s, error: %s",
                self._process.returncode(),
                err,
            )
            raise ProbeException("cento runtime error")

        # Wait till cento finishes
        Tool(
            f"while pidof {self._cmd.split(' ', 1)[0]} > /dev/null; do :; done",
            executor=self._executor,
            sudo=self._sudo,
            failure_verbosity="silent",
        ).run()

        self._process = None
        self.host_statistics.stop()
        self._after_stop()

    def cleanup(self):
        """
        Clean any artifacts created by the connector or the active probe itself.
        """
        Tool(f"rm -rf {self._local_workdir}").run()
        self.host_statistics.cleanup()

    def download_logs(self, directory: str):
        """
        Download logs to the given directory.

        Args:
            directory (str): Path to a local directory where logs should be stored.
        """
        try:
            shutil.move(self._log_file, directory)
            self.host_statistics.get_csv(directory)
        except PermissionError as err:
            logging.getLogger().warning("Cannot download ipfixprobe log, %s", err)

    def get_timeouts(self) -> tuple[int, int]:
        """
        Get active and inactive timeouts of the probe (in seconds).

        Returns:
            tuple: active_timeout, inactive_timeout
        """
        return self._timeouts

    def set_prefilter(self, ip_ranges: list[str]) -> None:
        """
        Set probe input filter. Probe will drop all traffic except specified IP ranges.
        """
        raise NotImplementedError
