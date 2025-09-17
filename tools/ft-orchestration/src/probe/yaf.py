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
from src.probe.mpstat import MpStat
from src.probe.probe_target import ProbeTarget


@typed_dataclass
@dataclass
class YafSettings(ABC):
    """
    These settings can be set in probes.yml under `connector:`.
    Example:
        connector:
            time_elements: 1
            input:
                type: "pcap"
    For possible values see <yaf_compile_dir>/etc/yaf.init or https://tools.netsa.cert.org/yaf2/yaf.init.html
    """

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
        cache_size=None,
        rss_queues: int = 1,
        **kwargs: dict,
    ):
        if len(interfaces) > 1:
            raise NotImplementedError
        kwargs["input"] = YafSettings.InputOptions(
            inf=interfaces[0].name if interfaces else None, **(kwargs.get("input", {}))
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

        if cache_size:
            kwargs["maxflows"] = 2**cache_size

        self._settings = YafSettings(
            idle_timeout=inactive_timeout,
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

        assert_tool_is_installed("yaf", executor)

        self._local_workdir = tempfile.mkdtemp()
        self._log_file = path.join(self._local_workdir, "yaf.log")
        self._config_file = path.join(self._local_workdir, "settings.conf")
        self._cmd = None
        self.host_statistics = MpStat(stats_executor, "yaf")
        self._rsync = Rsync(executor)
        self._rss_queues_pcap = rss_queues

    def _write_config(self, settings: YafSettings):
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
            Tool(
                f"ethtool --set-channels {self._settings.input.inf} combined {self._rss_queues_pcap}",
                executor=self._executor,
                sudo=self._sudo,
            ).run()

    def start(self, start_stats: bool = True, stop_running: bool = True):
        """
        Start the probe.
        """
        logging.getLogger().info(
            "Starting yaf exporter on %s.", self._settings.input.inf
        )

        if stop_running:
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

        if start_stats:
            self.host_statistics.start()

    def _after_stop(self):
        pass

    def _stop_process(self, pid):
        """
        Stop exporter process.
        """

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
        # TODO: Implement
        raise NotImplementedError

    def get_special_fields(self):
        """
        Return dictionary of exported fields that need special evaluation.
        """
        # TODO: Implement
        raise NotImplementedError

    def stop(self):
        """
        Stop the probe.
        """
        # if process not running, method has no effect
        if self._process is None:
            return

        logging.getLogger().info("Stopping yaf exporter.")

        stdout = []
        try:
            stdout, _ = self._process.stop()
        except ExecutableProcessError:
            pass

        while self._process.is_running():
            time.sleep(0.1)

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
        """
        Clean any artifacts created by the connector or the active probe itself.
        """
        Tool(f"rm -rf {self._local_workdir}").run()
        self._rsync.wipe_data_directory()
        Tool(
            f"rmdir {self._rsync.get_data_directory()}",
            executor=self._executor,
            sudo=self._sudo,
        )
        self.host_statistics.cleanup()

    def download_logs(self, directory: str):
        """
        Download logs to the given directory.

        Args:
            directory (str): Path to a local directory where logs should be stored.
        """
        try:
            shutil.move(self._log_file, directory)
            shutil.move(self._config_file, directory)
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


class YafPfring(Yaf):
    def __init__(
        self,
        executor: Executor,
        target: ProbeException,
        protocols: List[str],
        interfaces: List[InterfaceCfg],
        rss_queues: int = 1,
        **kwargs,
    ):
        super().__init__(
            executor,
            target,
            protocols,
            interfaces=[],
            **kwargs,
        )
        self._rss_queues = rss_queues
        self._yaf_settings = self._settings
        self._interfaces = [interface.name for interface in interfaces]

        self._yaf_instances: List[Yaf] = []
        self._executors = self._duplicate_executor(self._executor, rss_queues)
        inf_speed = interfaces[0].speed
        for i in range(rss_queues):
            in_inf = f"{self._interfaces[0]}@{i}"
            instance = Yaf(
                interfaces=[InterfaceCfg(in_inf, inf_speed)],
                target=target,
                protocols=protocols,
                executor=self._executors[i],
                **kwargs,
            )
            instance._log_file = path.join(instance._local_workdir, f"yaf_{i}.log")
            instance._config_file = path.join(
                instance._local_workdir, f"settings_{i}.conf"
            )
            self._yaf_instances.append(instance)

    def _duplicate_executor(self, executor: Executor, num: int = 1) -> List[Executor]:
        executors = []
        for i in range(num):
            if isinstance(executor, RemoteExecutor):
                connection: Connection = executor.get_connection()
                executors.append(
                    RemoteExecutor(executor.get_host(), **connection.connect_kwargs)
                )
            else:
                executors.append(LocalExecutor())

        return executors

    def _set_rss_queues(self, interface_name):
        Tool(
            f"ethtool --set-channels {interface_name} combined {self._rss_queues}",
            executor=self._executor,
            sudo=self._sudo,
        ).run()

    def _before_start(self):
        for ifc in self._interfaces:
            name = ifc.split(":", 1)[-1]
            Tool(
                f"ip link set {name} up", executor=self._executor, sudo=self._sudo
            ).run()
            Tool(
                f"ip link set {name} mtu {self._mtu}",
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
        self._before_start()

        for instance in self._yaf_instances:
            instance.start(False, False)

        self.host_statistics.start()

    def stop(self):
        """
        Stop the probe.
        """

        for instance in self._yaf_instances:
            instance.stop()

        # wait for all yaf instances to finish
        Tool(
            "while pidof yaf > /dev/null; do :; done",
            executor=self._fallback_executor,
            sudo=self._sudo,
            failure_verbosity="silent",
        ).run()

        self.host_statistics.stop()

        self._after_stop()

    def _after_stop(self):
        pass  # don't need to unload zc driver, acts like normal driver

    def cleanup(self):
        """
        Clean up all Yaf instances and their artifacts.
        """
        super().cleanup()
        for instance in self._yaf_instances:
            instance.cleanup()

    def download_logs(self, directory: str):
        """
        Download logs for all Yaf instances to the given directory.
        """
        for instance in self._yaf_instances:
            instance.download_logs(directory)

    def _get_driver(self, interface_name):
        driver, _ = Tool(
            f"pf_ringcfg --list-interfaces | grep {interface_name} | grep -o 'Driver: [^ ]*'",
            executor=self._executor,
            sudo=self._sudo,
            failure_verbosity="silent",
        ).run()
        if len(driver.split(" ")) < 2:
            return

        return driver.split(" ")[1].strip()

    def _switch_to_zc(self, interface_name: str):
        if "@" in interface_name:
            interface_name = interface_name.split("@", 1)[0]
        driver = self._get_driver(interface_name)
        if not driver:
            return
        if not driver.endswith("_zc"):
            Tool(
                f"pf_ringcfg --configure-driver {driver} --rss-queues 0",
                executor=self._executor,
                sudo=self._sudo,
            ).run()
            time.sleep(5)

    def _switch_back_zc(self, interface_name: str):
        driver = self._get_driver(interface_name)
        if not driver:
            return
        if not driver.endswith("_zc"):
            return
        driver = driver[:-3]
        Tool(
            f"nohup pf_ringcfg --configure-driver {driver}",
            executor=self._executor,
            sudo=self._sudo,
        ).run()
