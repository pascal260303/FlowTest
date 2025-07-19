from abc import ABC
from dataclasses import dataclass, fields, is_dataclass
import logging
from os import path
import shutil
import tempfile
import time
from typing import List, Optional
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
    Rsync,
)
from fabric import Connection
from src.probe.pidstat import PidStat
from src.probe.probe_target import ProbeTarget


@typed_dataclass
@dataclass
class YafSettings(ABC):
    @typed_dataclass
    @dataclass
    class InputOptions(ABC):
        inf: Optional[str] = None
        type: str = "pcap"
        export_interface: Optional[bool] = None
        file: Optional[str] = None
        noerror: Optional[str] = None
        force_read_all: bool = True

    input: Optional[InputOptions] = None

    @typed_dataclass
    @dataclass
    class OutputOptions(ABC):
        file: Optional[str] = None
        host: Optional[str] = None
        port: Optional[str] = None
        protocol: Optional[str] = None
        daemon: Optional[str] = None
        groups: Optional[str] = None
        groupby: Optional[str] = None
        rotate: Optional[str] = None
        lock: Optional[str] = None
        udp_temp_timeout: Optional[int] = 600

    output: Optional[OutputOptions] = None

    @typed_dataclass
    @dataclass
    class DecodeOptions(ABC):
        gre: Optional[bool] = None
        vxlan: Optional[bool] = None
        geneve: Optional[bool] = None
        ip4_only: Optional[bool] = None
        ip6_only: Optional[bool] = None
        no_frag: Optional[bool] = None

    decode: Optional[DecodeOptions] = None

    vxlan_ports: Optional[set[int]] = None

    geneve_ports: Optional[set[int]] = None

    @typed_dataclass
    @dataclass
    class ExportOptions(ABC):
        silk: Optional[bool] = False
        uniflow: bool = True
        force_ip6: Optional[bool] = False
        flow_stats: Optional[bool] = False
        delta: bool = True  # Required for packet and byte counter
        mac: Optional[bool] = False
        metadata: Optional[bool] = False

    export: Optional[ExportOptions] = None

    time_elements: Optional[int | str] = (
        1  # 1 = milliseconds, 2 = microseconds, 3 = nanoseconds
    )

    active_timeout: int = 300
    idle_timeout: int = 50

    filter: Optional[str] = None

    # APPLICATION LABELING OPTIONS
    applabel: Optional[bool] = None
    applabel_rules: Optional[str] = None

    maxpayload: Optional[int] = None
    maxexport: Optional[int] = None
    export_payload: Optional[bool] = None
    export_payload_applabels: Optional[str] = None
    udp_payload: Optional[bool] = None
    stats: int = 0
    no_tombstone: Optional[bool] = True
    tombstone_configured_id: Optional[int] = None
    ingress: Optional[int] = None
    egress: Optional[int] = None
    obdomain: Optional[int] = None
    maxflows: Optional[int] = None
    maxfrags: Optional[int] = None
    udp_uniflow: Optional[int] = None

    # Passive OS Fingerprinting (p0f) OPTIONS
    p0fprint: Optional[bool] = None
    fpexport: Optional[bool] = None
    p0f_fingerprints: Optional[str] = None

    # nDPI OPTIONS
    ndpi: Optional[bool] = None
    ndpi_proto_file: Optional[str] = None

    @typed_dataclass
    @dataclass
    class PluginOptions(ABC):
        name: Optional[str] = None
        options: Optional[str] = None
        conf: Optional[str] = None

    plugin: Optional[set[PluginOptions]] = None

    @typed_dataclass
    @dataclass
    class PCAPOptions(ABC):
        path: Optional[str] = None
        maxpcap: Optional[int] = None
        pcap_timer: Optional[int] = None
        meta: Optional[str] = None

    pcap: Optional[PCAPOptions] = None

    @typed_dataclass
    @dataclass
    class TLSOptions(ABC):
        ca: Optional[str] = None
        cert: Optional[str] = None
        key: Optional[str] = None

    tls: Optional[TLSOptions] = None

    @typed_dataclass
    @dataclass
    class LoggingOptions(ABC):
        spec: Optional[str] = None
        level: Optional[str] = None

    log: Optional[LoggingOptions] = None


class Yaf(ProbeInterface):
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
        inactive_timeout: int = 50,
        **kwargs: dict,
    ):
        if len(interfaces) > 1:
            raise NotImplementedError
        kwargs["input"] = YafSettings.InputOptions(
            inf=interfaces[0].name, **(kwargs.get("input", {}))
        )
        kwargs["output"] = YafSettings.OutputOptions(
            host=target.host,
            port=str(target.port),
            protocol=target.protocol,
            **(kwargs.get("output", {})),
        )
        kwargs["decode"] = YafSettings.DecodeOptions(**(kwargs.get("decode", {})))
        kwargs["export"] = YafSettings.ExportOptions(**(kwargs.get("export", {})))
        kwargs["plugin"] = (
            {YafSettings.PluginOptions(**plopt) for plopt in kwargs.get("plugin")}
            if "plugin" in kwargs and kwargs["plugin"]
            else None
        )
        kwargs["pcap"] = YafSettings.PCAPOptions(**(kwargs.get("pcap", {})))
        kwargs["tls"] = YafSettings.TLSOptions(**(kwargs.get("tls", {})))
        kwargs["log"] = YafSettings.LoggingOptions(**(kwargs.get("log", {})))
        self._settings = YafSettings(idle_timeout=inactive_timeout, **kwargs)
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
        if protocols:
            raise NotImplementedError(
                "To support protocol filtering a ndpi_proto_file must be created which is currently not implemented"
            )

        self._verbose = verbose
        self._timeouts = (
            self._settings.active_timeout,
            self._settings.idle_timeout,
        )
        self._mtu = mtu
        self._sudo = sudo
        self._interface = interfaces[0].name

        assert_tool_is_installed("yaf", executor)

        self._local_workdir = tempfile.mkdtemp()
        self._log_file = path.join(self._local_workdir, "yaf.log")
        self._config_file = path.join(self._local_workdir, "settings.conf")
        self._cmd = None
        self.host_statistics = PidStat(stats_executor, "yaf")
        self._rsync = Rsync(executor)

    def _write_config(self, settings: YafSettings):
        # TODO: Implement

        def to_lua_literal(value) -> str:
            match value:
                case bool():
                    return "true" if value else "false"
                case int() | float():
                    return str(value)
                case str():
                    return f'"{value}"'
                case set() | list():
                    return "{" + ", ".join(to_lua_literal(v) for v in value) + "}"
                case None:
                    return None
                case _:
                    return str(value)

        def dataclass_to_lua_table(obj, sep: str = "\n") -> str:
            lua = []
            for field in fields(obj):
                val = getattr(obj, field.name)
                if val is None:
                    continue
                key = field.name
                if is_dataclass(val):
                    nested = dataclass_to_lua_table(val, sep=", ")
                    if not nested:
                        continue
                    lua.append(f"{key} = {{{nested}}}")
                else:
                    literal = to_lua_literal(val)
                    if literal is None:
                        continue
                    lua.append(f"{key} = {literal}")
            return sep.join(lua)

        with open(self._config_file, "w") as f:
            f.write("-- Generated settings.conf (Lua format for --config)\n\n")
            f.write(dataclass_to_lua_table(settings))
            f.write("\n")

    def _prepare_cmd(self, config_file: str) -> str:
        args = ["yaf"]
        args.extend(["-c", config_file])
        if self._verbose:
            args.append("--verbose")

        return " ".join(args)

    def _before_start(self):
        self._write_config(self._settings)
        self._cmd = self._prepare_cmd(self._rsync.push_path(self._config_file))
        if self._settings.input.type == "pcap":
            Tool(
                f"ip link set {self._settings.input.inf} up",
                executor=self._executor,
                sudo=self._sudo,
            ).run()
            Tool(
                f"ip link set {self._settings.input.inf} mtu {self._mtu}",
                executor=self._executor,
                sudo=self._sudo,
            ).run()

    def start(self):
        """Start the probe."""
        logging.getLogger().info(
            "Starting yaf exporter on %s.", self._settings.input.inf
        )

        # check and stop running yaf instance
        check_running_cmd = "pidof 'yaf'"
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
                "Unable to start probe on %s. yaf return code: %d, error: %s",
                ",".join(self._settings.input.inf),
                return_code,
                err,
            )
            raise ProbeException("yaf startup error")

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
        """Get list of IPFIX fields the probe may export in its current configuration."""
        # TODO: Implement
        raise NotImplementedError

    def get_special_fields(self):
        """Return dictionary of exported fields that need special evaluation."""
        # TODO: Implement
        raise NotImplementedError

    def stop(self):
        """Stop the probe."""
        # if process not running, method has no effect
        if self._process is None:
            return

        logging.getLogger().info("Stopping yaf exporter.")

        stdout = []
        try:
            stdout, _ = self._process.stop()
        except ExecutableProcessError:
            pass

        # Wait till yaf finishes
        Tool(
            f"while pidof {self._cmd.split(' ', 1)[0]} > /dev/null; do :; done",
            executor=self._executor,
            sudo=self._sudo,
            failure_verbosity="silent",
        ).run()

        if self._process.returncode() > 0:
            # stderr is redirected to stdout
            # Since stdout could be filled with normal output, print only last 1 line#
            err = stdout[-1] if stdout else ""
            logging.getLogger().error(
                "yaf runtime error: %s, error: %s",
                self._process.returncode(),
                err,
            )

        self._process = None
        self.host_statistics.stop()
        self._after_stop()

    def cleanup(self):
        """Clean any artifacts which were created by the connector or the active probe itself."""
        Tool(f"rm -rf {self._local_workdir}").run()
        self._rsync.wipe_data_directory()
        Tool(
            f"rmdir {self._rsync.get_data_directory()}",
            executor=self._executor,
            sudo=self._sudo,
        )
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
            shutil.copy(self._config_file, directory)
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
        raise NotImplementedError
