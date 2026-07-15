from ipaddress import IPv6Address
import logging
import shutil
import tempfile
import time
from abc import ABC
from dataclasses import dataclass, field, fields
from os import path
from typing import List, Optional

from lbr_testsuite.executable import (
    ExecutableProcessError,
    Executor,
    Rsync,
    Tool,
)
from src.probe.process_group import Daemon
from src.common.tool_is_installed import assert_tool_is_installed
from src.common.typed_dataclass import typed_dataclass
from src.common.utils import duplicate_executor
from src.config.common import InterfaceCfg
from src.probe.interface import ProbeException, ProbeInterface
from src.stats.merged import MergedStats
from src.probe.probe_target import ProbeTarget


@typed_dataclass
@dataclass
class PmacctSettings(ABC):
    """
    These settings can be set in probes.yml under `connector:`.
    Example:
        connector:
            time_elements: 1
            input:
                type: "pcap"
    For possible values see http://www.pmacct.net/CONFIG-KEYS-1.7.9
    """

    nfprobe_receiver: str
    pcap_interface: str
    daemonize: bool = False
    aggregate: list = field(
        default_factory=lambda: [
            "src_host",
            "dst_host",
            "src_port",
            "dst_port",
            "proto",
        ]
    )
    plugins: list = field(default_factory=lambda: ["nfprobe"])
    nfprobe_version: int = 10
    nfprobe_engine: Optional[str] = None
    nfprobe_timeouts: dict = field(
        default_factory=lambda: {
            "tcp": 30,
            "udp": 30,
            "icmp": 30,
            "general": 30,
            "maxlife": 300,
            "expint": 1,
        }
    )
    nfprobe_maxflows: Optional[int] = None
    extras: Optional[dict] = None


class Pmacct(ProbeInterface):
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
        inactive_timeout: int = 30,
        active_timeout: int = 300,
        cache_size=None,
        rss_queues: int = 1,
        binary: str = "pmacctd",
        mem_limit=None,
        cpu_limit=None,
        hw_ring_size=8192,
        **kwargs: dict,
    ):
        # initialize PmacctSettings and map FlowTest values to pmacct values
        if len(interfaces) > 1:
            raise NotImplementedError
        kwargs["pcap_interface"] = interfaces[0].name if interfaces else None

        if isinstance(target.host, IPv6Address):
            kwargs["nfprobe_receiver"] = f"[{target.host}]:{target.port}"
        else:
            kwargs["nfprobe_receiver"] = f"{target.host}:{target.port}"

        if target.protocol != "udp":
            raise NotImplementedError(
                f"pmacctd only supports udp and dtls and only udp is implemented here, not {target.protocol}"
            )

        if cache_size:
            kwargs["nfprobe_maxflows"] = 2**cache_size

        default_timeouts: dict = PmacctSettings.__dataclass_fields__[
            "nfprobe_timeouts"
        ].default_factory()
        user_timeouts = kwargs.pop("nfprobe_timeouts", {})
        merged_timeouts = {**default_timeouts, **user_timeouts}
        merged_timeouts.update(
            {
                "tcp": inactive_timeout,
                "tcp.rst": inactive_timeout,
                "tcp.fin": inactive_timeout,
                "udp": inactive_timeout,
                "icmp": inactive_timeout,
                "general": inactive_timeout,
                "maxlife": active_timeout,
            }
        )
        kwargs["nfprobe_timeouts"] = merged_timeouts

        # Split known and extra settings and instantiate PmacctSettings from kwargs
        settings_names = [f.name for f in fields(PmacctSettings)]
        defined_settings = {k: v for k, v in kwargs.items() if k in settings_names}
        extras = {k: v for k, v in kwargs.items() if k not in settings_names}
        if "extras" in defined_settings.keys():
            extras.update(defined_settings.get("extras", {}))
            del defined_settings["extras"]
        self._settings = PmacctSettings(**defined_settings, extras=extras or None)

        # store internally required variables
        self._executor = executor
        self._fallback_executor, stats_executor = duplicate_executor(executor, 2)
        if protocols:
            raise NotImplementedError(
                "To support protocol filtering ndpi must be used which is currently not implemented"
            )

        self._verbose = verbose
        self._timeouts = (active_timeout, inactive_timeout)
        self._mtu = mtu
        self._sudo = sudo
        self._binary = binary
        self._cpu_limit = cpu_limit
        self._mem_limit = mem_limit
        self._hw_ring_size = hw_ring_size

        assert_tool_is_installed(self._binary, executor)

        self._local_workdir = tempfile.mkdtemp()
        self._log_file = path.join(self._local_workdir, f"{self._binary}.log")
        self._config_file = path.join(self._local_workdir, "settings.conf")
        self._cmd = None
        self.host_statistics = MergedStats(stats_executor, self._binary)
        self._rsync = Rsync(executor)
        self._rss_queues_pcap = rss_queues

    def _write_config(self, settings: PmacctSettings):
        config = {}

        def to_config_literal(value) -> str:
            match value:
                case bool():
                    return "true" if value else "false"
                case set() | list():
                    return ", ".join(to_config_literal(v) for v in value)
                case dict():
                    val = []
                    for k, v in value.items():
                        val.append(f"{k}={to_config_literal(v)}")
                    return ":".join(val)
                case None:
                    return None
                case _:
                    return str(value)

        for f in fields(settings):
            value = to_config_literal(getattr(settings, f.name))
            if value is None or not value:
                continue
            config.update({f.name: value})

        if settings.extras:
            for key, value in settings.extras.items():
                value = to_config_literal(value)
                if value is None or not value:
                    continue
                if key in config.keys():
                    logging.warning(
                        f"Duplicate config: {key}: {value} overwrites {config[key]}"
                    )
                config.update({key: value})

        with open(self._config_file, "w") as f:
            f.write("! Generated by FlowTest for -f option\n\n")
            f.write("\n".join(f"{k}: {v}" for k, v in config.items()))
            f.write("\n")

    def _prepare_cmd(self, config_file: str) -> str:
        args = [self._binary]
        args.extend(["-f", config_file])

        return " ".join(args)

    def _before_start(self):
        self._write_config(self._settings)
        self._cmd = self._prepare_cmd(self._rsync.push_path(self._config_file))

        Tool(
            f"ip link set {self._settings.pcap_interface} up",
            executor=self._executor,
            sudo=self._sudo,
        ).run()
        Tool(
            f"ip link set {self._settings.pcap_interface} mtu {self._mtu}",
            executor=self._executor,
            sudo=self._sudo,
        ).run()
        Tool(
            f"ethtool -G {self._settings.pcap_interface} rx {self._hw_ring_size}",
            executor=self._executor,
            sudo=self._sudo,
        ).run()
        Tool(
            f"ethtool -K {self._settings.pcap_interface} gro off gso off tso off",
            executor=self._executor,
            sudo=self._sudo,
        ).run()
        Tool(
            f"ethtool --set-channels {self._settings.pcap_interface} combined $(nproc)",
            executor=self._executor,
            sudo=self._sudo,
        ).run()
        Tool(
            f"ethtool -X {self._settings.pcap_interface} hfunc toeplitz hkey 6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a equal {self._rss_queues_pcap}",
            executor=self._executor,
            sudo=self._sudo,
        ).run()
        Tool(
            f"ethtool --set-channels {self._settings.pcap_interface} combined {self._rss_queues_pcap}",
            executor=self._executor,
            sudo=self._sudo,
        ).run()
        Tool(
            f"ethtool -N {self._settings.pcap_interface} rx-flow-hash tcp4 sd",
            executor=self._executor,
            sudo=self._sudo,
        ).run()
        Tool(
            f"ethtool -N {self._settings.pcap_interface} rx-flow-hash udp4 sd",
            executor=self._executor,
            sudo=self._sudo,
        ).run()
        Tool(
            f"ethtool -N {self._settings.pcap_interface} rx-flow-hash tcp6 sd",
            executor=self._executor,
            sudo=self._sudo,
        ).run()
        Tool(
            f"ethtool -N {self._settings.pcap_interface} rx-flow-hash udp6 sd",
            executor=self._executor,
            sudo=self._sudo,
        ).run()

    def start(self):
        """
        Start the probe.
        """
        logging.getLogger().info(
            f"Starting {self._binary} exporter on {self._settings.pcap_interface}."
        )

        # check and stop running pmacctd instance
        check_running_cmd = f"pidof '{self._binary}'"
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

        self._process = Daemon(
            self._cmd,
            executor=self._executor,
            sudo=self._sudo,
            cpu_limit=self._cpu_limit,
            mem_limit=self._mem_limit,
        )
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
                "Unable to start probe on %s. %s return code: %d, error: %s",
                self._settings.pcap_interface,
                self._binary,
                return_code,
                err,
            )
            raise ProbeException(f"{self._binary} startup error")

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

        logging.getLogger().info(f"Stopping {self._binary} exporter.")

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
                f"{self._binary} runtime error: %s, error: %s",
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
