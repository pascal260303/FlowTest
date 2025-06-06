"""
Author(s): Jan Sobol <sobol@cesnet.cz>

Copyright: (C) 2022 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

Library for managing ipfixprobe.
"""

import logging
import shutil
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from fabric import Connection
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from lbr_testsuite.executable import Daemon, Executor, Rsync, Tool, RemoteExecutor, LocalExecutor
from src.common.required_field import required_field
from src.common.tool_is_installed import assert_tool_is_installed
from src.common.typed_dataclass import bool_convertor, typed_dataclass
from src.config.common import InterfaceCfg
from src.probe.interface import ProbeException, ProbeInterface
from src.probe.probe_target import ProbeTarget
from lbr_testsuite.executable import ExecutableProcessError

PROTOCOLS_TO_PLUGINS = {
    "eth": "basic",
    "tcp": "basicplus",
    "ipv4": "basicplus",
    "ipv6": "basicplus",
    "dns": "dns",
    "http": "http",
    "tls": "tls",
    "wg": "wg",
    "ovpn": "ovpn",
    # "vlan": "",    # unsupported
    # "mpls": "",    # unsupported
    # "gre": "",     # unsupported
    # "vxlan": "",   # unsupported
    # "icmpv6": "",  # unsupported
    # "icmp": "",    # unsupported
}


FIELDS = {
    "basic": [
        "dst_mac",
        "src_mac",
        "ip_version",
        "dst_ip",
        "src_ip",
        "bytes",
        "packets",
        "dst_port",
        "src_port",
        "protocol",
        "tcp_flags",
    ],
    "basicplus": [
        "ttl",
        "tcp_options",
        "tcp_syn_size",
    ],
    "http": [
        "http_method",
        "http_host",
        "http_url",
        "http_agent",
        "http_referer",
        "http_status_code",
        "http_content_type",
    ],
    "tls": [
        "tls_sni",
        "tls_alpn",
        "tls_server_version",
        "tls_ja3",
    ],
    "dns": [
        "dns_id",
        "dns_req_query_type",
        "dns_req_query_class",
        "dns_req_query_name",
        "dns_resp_rcode",
        "dns_resp_rr.ttl",
        "dns_resp_rr.data",
    ],
    "wg": ["wg_conf_level", "wg_src_peer", "wg_dst_peer"],
    "ovpn": ["ovpn_conf_level"],
}


SPECIAL_FIELDS = {"dns_resp_rr": "OneInArray", "http_agent": "StartsWith"}


class IpfixprobePluginType(Enum):
    """Basic types of plugins used by ipfixprobe."""

    INPUT = 0
    OUTPUT = 1
    STORAGE = 2
    PROCESS = 3


@typed_dataclass
@dataclass
# pylint: disable=too-many-instance-attributes
class IpfixprobeSettings(ABC):
    """Structure used to hold ipfixprobe settings which are passed to Ipfixprobe class.

    Attributes
    ----------
    cache_size: int, optional
        Cache size exponent to the power of two.
    cache_line_size: int, optional
        Cache line size exponent to the power of two.
    active_timeout: int, optional
        Active timeout in seconds.
    inactive_timeout: int, optional
        Inactive timeout in seconds.
    split_biflows: bool, optional
        When True, biflows are splitted into single flows before export.
    mtu_size: int, optional
        Maximum size of ipfix packet payload sent.
    exporter_id: int, optional
        Exporter identification.
    input_queue_size: int, optional
        Size of queue between input and storage plugins (-q ipfixprobe arg).
    input_packet_block_size: int, optional
        Size of input queue packet block (-b ipfixprobe arg).
    output_queue_size: int, optional
        Size of queue between storage and output plugins (-Q ipfixprobe arg).
    packet_buffer_size: int, optional
        Size of packet buffer (-B ipfixprobe arg).
    """

    # flow cache settings
    cache_size: Optional[int] = None
    cache_line_size: Optional[int] = None
    active_timeout: int = 300
    inactive_timeout: int = 30
    split_biflows: bool = False

    # output plugin (ipfix) settings
    mtu_size: Optional[int] = None
    exporter_id: Optional[int] = None

    # common settings
    input_queue_size: Optional[int] = None
    input_packet_block_size: Optional[int] = None
    output_queue_size: Optional[int] = None
    packet_buffer_size: Optional[int] = None


@typed_dataclass
@dataclass
class IpfixprobeRawSettings(IpfixprobeSettings):
    """Settings for IpfixprobeRaw input variant.

    Attributes
    ----------
    interfaces: List[str], required
        Enabled network input interfaces.
    fanout: bool, optional
        Enable packet fanout.
    fanout_id: int, optional
        Optional id for packet fanout.
    blocks: int, optional
        Number of packet blocks (should be power of two num).
    packets: int, optional
        Number of packets in block (should be power of two num).
    """

    interfaces: List[str] = required_field()

    # for simplicity, same values of following params are used for each enabled interface
    fanout: Optional[bool] = field(default=None, metadata={"convert_func": bool_convertor})
    fanout_id: Optional[int] = None
    blocks: Optional[int] = None
    packets: Optional[int] = None

    def __post_init__(self):
        assert len(self.interfaces) > 0


@typed_dataclass
@dataclass
class IpfixprobeDpdkSettings(IpfixprobeSettings):
    """Settings for IpfixprobeDpdk input variant.

    Attributes
    ----------
    devices: List[str], required
        Allowed devices in format <[domain:]bus:devid.func>. EAL parameter.
    lcores: str, optional
        Map lcore set to physical cpu set. EAL parameter.
    memory: int, optional
        Memory to allocate (MB). EAL parameter.
    file_prefix: str, optional
        Prefix for hugepage filenames. EAL parameter.
    queues_count: int, optional
        Number of RX queues. Default: 1.
    mbuf_size: int, optional
        Size of the MBUF packet buffer.
    mempool_size: int, optional
        Size of the memory pool for received packets.
    """

    # EAL params
    devices: List[str] = required_field()
    lcores: Optional[str] = None
    memory: Optional[int] = None
    file_prefix: Optional[str] = None

    # dpdk plugin params, same values for all devices
    queues_count: int = 1
    mbuf_size: Optional[int] = None
    mempool_size: Optional[int] = None

    def __post_init__(self):
        assert len(self.devices) > 0


@typed_dataclass
@dataclass
class IpfixprobeNdpSettings(IpfixprobeSettings):
    """Settings for IpfixprobeNdp input variant.

    Attributes
    ----------
    devices: List[str], required
        Paths to device files.
    dma_channels_map: dict[int, int], optional
        Binary mask that specifies for which DMA channels to create instance of ndp input plugin.
    """

    devices: List[str] = required_field()
    dma_channels_map: dict[int, int] = field(default_factory=lambda: {0: 1})

    def __post_init__(self):
        assert len(self.devices) > 0


class IpfixprobeStats:
    """Object representing stats from ipfixprobe run.

    Attributes
    ----------
    input: list
        Input interfaces stats.
    output: list
        Output flow export stats.
    """

    def __init__(self, stdout: List[str]) -> None:
        """Init stats object.

        Parameters
        ----------
        stdout: list
            Ipfixprobe process output splitted by lines.
        """

        self.input = []
        self.output = []
        self._parse(stdout)

    def _parse(self, stdout: List[str]) -> None:
        """Parse from stdout.

        Parameters
        ----------
        stdout: list
            Ipfixprobe process output splitted by lines.
        """

        active_part = self.input
        active_columns = []
        for line in [l.strip() for l in stdout]: # noqa
            if "Input stats" in line:
                active_part = self.input
                continue
            if "Output stats" in line:
                active_part = self.output
                continue

            cols = line.split()
            if len(cols) > 0:
                if cols[0] == "#":
                    active_columns = []
                    for column_name in cols[1:]:
                        active_columns.append(column_name)
                elif cols[0].isdigit():
                    record = {}
                    for i, col in enumerate(cols[1:]):
                        record[active_columns[i]] = int(col) if col.isdigit() else col
                    active_part.append(record)

    def __repr__(self) -> str:
        return f"INPUT:\n{self.input}\nOUTPUT:\n{self.output}"

    def __str__(self) -> str:
        return self.__repr__()


# pylint: disable=too-many-instance-attributes
class Ipfixprobe(ProbeInterface, ABC):
    """Class for invoking and managing ipfixprobe process on host.

    Attributes
    ----------
    _executor : lbr_testsuite.executable.Executor
        Initialized executor object with the deployed probe.
    _cmd: string
        Ipfixprobe command for startup.
    _process: invoke.runners.Promise
        Representation of ipfixprobe process.
    _sudo: bool
        Run ipfixprobe process as administrator with sudo.
    _last_run_stats: IpfixprobeStats, optional
        Last run statistics. None if last run failed or ipfixprobe did not run.
    _ifc_names: list(str)
        List of string names of enabled input interfaces. Used primarily in log messages.
    _enabled_plugins: list(str)
        List of enabled process plugins. "basic" pseudo plugin is not listed.
    """

    # pylint: disable=super-init-not-called
    def __init__(
        self,
        executor: Executor,
        target: ProbeTarget,
        protocols: List[str],
        interfaces: List[InterfaceCfg],
        verbose: bool = False,
        settings: IpfixprobeSettings = None,
        sudo: bool = False,
    ):
        """Init ipfixprobe connector.

        Parameters
        ----------
        executor : lbr_testsuite.executable.Executor
            Initialized executor object with the deployed probe.
        target : src.probe.ProbeTarget
            Export target where all flow data generated by the probe should be sent.
        protocols : list
            List of networking protocols which the probe should parse and export.
        interfaces: list
            Network interfaces where the exporting process should be initiated.
        verbose : bool, optional
            If True, logs will collect all debug messages.
        settings : IpfixprobeSettings, optional
            Settings for ipfixprobe including input interface configuration.
        sudo : bool, optional
            Run ipfixprobe process as administrator with sudo.

        Raises
        ------
        ProbeException
            If missing ipfixprobe binary or any of required plugin.
        """

        self._executor = executor
        if isinstance(executor, RemoteExecutor):
            connection: Connection = executor.get_connection()
            self._fallback_executor = RemoteExecutor(executor.get_host(), **connection.connect_kwargs)
        else:
            self._fallback_executor = LocalExecutor()
        self._process = None
        self._sudo = sudo
        self._ifc_names = ",".join([ifc.name for ifc in interfaces])
        self._verbose = verbose
        self._enabled_plugins = []
        self._last_run_stats = None
        self._timeouts = (settings.active_timeout, settings.inactive_timeout)

        assert_tool_is_installed("ipfixprobe", executor)
        self._cmd = self._prepare_cmd(target, protocols, settings)

        self._local_workdir = tempfile.mkdtemp()
        self._log_file = Path(self._local_workdir, "ipfixprobe.log")

    def supported_fields(self) -> List[str]:
        """Returns list of IPFIX fields the probe may export in its current configuration.

        Returns
        -------
        List
            Fields which may present in the flows.
        """

        fields_2d = [FIELDS[p] for p in self._enabled_plugins + ["basic"]]
        return [p for sub in fields_2d for p in sub]

    def get_special_fields(self) -> Dict[str, str]:
        """Get list of IPFIX fields the probe may export in its current configuration
        and need special evaluation.

        Returns
        -------
        Dict
            of special fields with way to evaluate them
        """

        fields = self.supported_fields()
        return {name: value for name, value in SPECIAL_FIELDS.items() if name in fields}

    def start(self) -> None:
        """Start ipfixprobe process."""

        logging.getLogger().info("Starting ipfixprobe exporter on %s.", self._ifc_names)
        self._last_run_stats = None

        self._before_start()

        # check and stop running ipfixprobe instance
        check_running_cmd = "pidof 'ipfixprobe' 'ipfixprobed'"
        running_processes = Tool(check_running_cmd, executor=self._executor, failure_verbosity="silent").run()[0]
        if len(running_processes) > 0:
            running_pid = int(running_processes.split()[0])
            self._stop_process(running_pid)
            time.sleep(2)

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
                "Unable to start probe on %s. ipfixprobe return code: %d, error: %s",
                self._ifc_names,
                return_code,
                err,
            )
            raise ProbeException("ipfixprobe startup error")

    def stop(self) -> None:
        """Stop ipfixprobe process."""

        # if process not running, method has no effect
        if self._process is None:
            return

        logging.getLogger().info("Stopping ipfixprobe exporter.")
               
        command = self._cmd.split(" ",1)[0]
        Tool(f"kill $(pidof -s {command})", executor=self._fallback_executor, failure_verbosity="silent").run()
        
        stdout = []
        try:
            stdout, _ = self._process.stop()
        except ExecutableProcessError:
            pass

        if self._process.returncode() > 0:
            # stderr is redirected to stdout
            # Since stdout could be filled with normal output, print only last 1 line#
            err = stdout[-1]
            logging.getLogger().error("ipfixprobe runtime error: %s, error: %s", self._process.returncode(), err)
            self._last_run_stats = None
            raise ProbeException("ipfixprobe runtime error")

        with open(self._log_file, "r", encoding="utf-8") as file:
            log = file.readlines()
        self._last_run_stats = IpfixprobeStats(log)
        self._process = None

    def cleanup(self) -> None:
        """Clean any artifacts which were created by the connector or the active probe itself."""

        Rsync(self._executor).wipe_data_directory()
        Tool(f"rm -rf {self._local_workdir}/*").run()

    def download_logs(self, directory: str):
        """Download logs from ipfix probe.

        Parameters
        ----------
        directory : str
            Path to a local directory where logs should be stored.
        """

        try:
            shutil.copy(self._log_file, directory)
        except PermissionError as err:
            logging.getLogger().warning("Cannot download ipfixprobe log, %s", err)

    @property
    def last_run_stats(self) -> Optional[IpfixprobeStats]:
        """Get statistics of last ipfixprobe run.

        Returns
        -------
        IpfixprobeStats or None
            Last run statistics. None if last run failed or ipfixprobe did not run.
        """

        return self._last_run_stats

    def get_timeouts(self) -> tuple[int, int]:
        """Get active and inactive timeouts of the probe (in seconds).

        Returns
        -------
        tuple
            active_timeout, inactive_timeout
        """

        return self._timeouts

    def _check_plugin(self, name: str) -> None:
        """Check plugin compiled in ipfixprobe binary by trying plugin's help.

        Parameters
        ----------
        name : str
            Plugin name.

        Raises
        ------
        ProbeException
            If plugin is not found.
        """

        check = Tool(f"ipfixprobe -h {name}", executor=self._executor, failure_verbosity="silent").run()
        if check[0].strip() == f"No help available for {name}":
            logging.getLogger().error("Plugin '%s' not found by ipfixprobe binary.", name)
            raise ProbeException(f"Plugin '{name}' not found by ipfixprobe binary.")

    @abstractmethod
    def _prepare_cmd(self, target: ProbeTarget, protocols: List[str], settings: IpfixprobeSettings) -> str:
        """Prepare command to run ipfixprobe process with required settings.

        Parameters
        ----------
        target : src.probe.ProbeTarget
            Export target where all flow data generated by the probe should be sent.
        protocols : list
            List of networking protocols which the probe should parse and export.
        settings : IpfixprobeSettings
            Settings for ipfixprobe including input interface configuration.

        Returns
        -------
        str
            Assembled command.

        Raises
        ------
        ProbeException
            If any of required plugins is not found.
        """

        # cannot run ipfixprobe without input plugin - must be setup in derived class
        # example implementation:
        #
        #   args = ["ipfixprobe"]
        #   args += self._get_plugin_arg(IpfixprobePluginType.INPUT, "raw", [f"ifc={settings.interface}"])
        #   args += self._get_common_args(target, protocols, settings)
        #   return " ".join(args)

        raise NotImplementedError

    @staticmethod
    def _get_plugin_arg(plugin_type: IpfixprobePluginType, plugin_name: str, plugin_args: List[str]) -> Tuple[str, str]:
        """Prepare single plugin argument.

        Parameters
        ----------
        plugin_type: IpfixprobePluginType
            Type of plugin - input/output/process/storage.
        plugin_name: str
            Name of plugin to enable.
        plugin_args: list
            Arguments passed to plugin.

        Returns
        -------
        tuple(str, str)
            Plugin type flag and plugin params in string argument.
        """

        if plugin_type == IpfixprobePluginType.INPUT:
            flag = "-i"
        elif plugin_type == IpfixprobePluginType.OUTPUT:
            flag = "-o"
        elif plugin_type == IpfixprobePluginType.PROCESS:
            flag = "-p"
        elif plugin_type == IpfixprobePluginType.STORAGE:
            flag = "-s"
        else:
            raise ValueError("Not supported type of plugin.")

        str_args = ";".join([plugin_name] + plugin_args)

        return (flag, f'"{str_args}"')

    def _get_process_plugins_args(self, protocols: List[str]) -> List[str]:
        """Enable plugins by required protocols. Assembly argument for each plugin.
        Process plugin arguments are not supported. Phrase to enable is always in form '-p process_plugin'.

        Parameters
        ----------
        protocols : list
            List of networking protocols which the probe should parse and export.

        Returns
        -------
        list
            Arguments to enable plugins.

        Raises
        ------
        ProbeException
            If any of required plugins is not found.
        """

        args = []

        plugins = list({PROTOCOLS_TO_PLUGINS[p] for p in protocols if p in PROTOCOLS_TO_PLUGINS})

        for plugin in sorted(plugins):
            if plugin == "basic":
                continue
            self._check_plugin(plugin)
            args += self._get_plugin_arg(IpfixprobePluginType.PROCESS, plugin, [])
            self._enabled_plugins.append(plugin)

        return args

    # pylint: disable=too-many-branches
    def _get_common_args(self, target: ProbeTarget, protocols: List[str], settings: IpfixprobeSettings) -> List[str]:
        """Prepare args list with common settings - cache size, buffer sizes, queue sizes, timeouts, etc.

        Parameters
        ----------
        target : src.probe.ProbeTarget
            Export target where all flow data generated by the probe should be sent.
        protocols : list
            List of networking protocols which the probe should parse and export.
        settings : IpfixprobeSettings
            Settings for ipfixprobe with optional common settings.

        Returns
        -------
        list
            Common settings argument list.
        """

        args = []

        # storage plugin additional config
        cache_params = []

        if settings.cache_size:
            cache_params.append(f"s={settings.cache_size}")
        if settings.cache_line_size:
            cache_params.append(f"l={settings.cache_line_size}")
        if settings.active_timeout:
            cache_params.append(f"a={settings.active_timeout}")
        if settings.inactive_timeout:
            cache_params.append(f"i={settings.inactive_timeout}")
        if settings.split_biflows:
            cache_params.append("split")

        if len(cache_params) > 0:
            args += self._get_plugin_arg(IpfixprobePluginType.STORAGE, "cache", cache_params)

        # output plugin argument
        output_params = [f"h={target.host}", f"p={target.port}"]
        if target.protocol == "udp":
            output_params.append("udp")

        if settings.mtu_size:
            output_params.append(f"m={settings.mtu_size}")
        if settings.exporter_id:
            output_params.append(f"m={settings.exporter_id}")
        if self._verbose:
            output_params.append("v")

        args += self._get_plugin_arg(IpfixprobePluginType.OUTPUT, "ipfix", output_params)

        # process plugins arguments
        args += self._get_process_plugins_args(protocols)

        if settings.input_queue_size:
            args += ["-q", str(settings.input_queue_size)]
        if settings.input_packet_block_size:
            args += ["-b", str(settings.input_packet_block_size)]
        if settings.output_queue_size:
            args += ["-Q", str(settings.output_queue_size)]
        if settings.packet_buffer_size:
            args += ["-B", str(settings.packet_buffer_size)]
            
        # telemetry args
        
        args += ["-t", "/tmp/telemetry"]

        return args

    def _stop_process(self, pid):
        """Stop exporter process"""

        Tool(f"kill -2 {pid}", executor=self._executor, failure_verbosity="silent", sudo=True).run()
        ps_ec = Tool(f"ps -p {pid}", executor=self._executor, failure_verbosity="silent")
        for _ in range(5):
            ps_ec.run()
            if ps_ec.returncode() == 1:
                return
            time.sleep(1)
        logging.getLogger().warning("Unable to stop exporter process with SIGINT, using SIGKILL.")
        Tool(f"kill -9 {pid}", executor=self._executor, failure_verbosity="silent", sudo=True).run()

    def _before_start(self):
        """Do preparations before the probe start. Override this function in derived class."""


class IpfixprobeRaw(Ipfixprobe):
    """Implementation of Ipfixprobe connector with raw socket traffic capturing."""

    def __init__(
        self,
        executor: Executor,
        target: ProbeTarget,
        protocols: List[str],
        interfaces: List[InterfaceCfg],
        verbose: bool = False,
        mtu: int = 1522,
        sudo: bool = False,
        **kwargs: dict,
    ):
        interfaces_names = [ifc.name for ifc in interfaces]
        settings = IpfixprobeRawSettings(interfaces=interfaces_names, **kwargs)
        super().__init__(executor, target, protocols, interfaces, verbose, settings, sudo)
        self._mtu = mtu

    def _prepare_cmd(self, target: ProbeTarget, protocols: List[str], settings: IpfixprobeSettings) -> str:
        self._check_plugin("raw")

        if not isinstance(settings, IpfixprobeRawSettings):
            raise TypeError("In IpfixprobeRaw settings should be IpfixprobeRawSettings.")

        args = ["ipfixprobe"]

        for ifc in settings.interfaces:
            raw_params = [f"ifc={ifc}"]
            if settings.fanout:
                if settings.fanout_id:
                    raw_params.append(f"f={settings.fanout_id}")
                else:
                    raw_params.append("f")
            if settings.blocks:
                raw_params.append(f"b={settings.blocks}")
            if settings.packets:
                raw_params.append(f"p={settings.packets}")

            args += self._get_plugin_arg(IpfixprobePluginType.INPUT, "raw", raw_params)

        args += self._get_common_args(target, protocols, settings)
        return " ".join(args)

    def _before_start(self):
        for ifc in self._ifc_names.split(","):
            Tool(f"ip link set dev {ifc} up", executor=self._executor, sudo=True).run()
            Tool(f"ip link set dev {ifc} mtu {self._mtu}", executor=self._executor, sudo=True).run()


class IpfixprobeDpdk(Ipfixprobe):
    """Implementation of Ipfixprobe connector with dpdk traffic capturing."""

    def __init__(
        self,
        executor: Executor,
        target: ProbeTarget,
        protocols: List[str],
        interfaces: List[InterfaceCfg],
        verbose: bool = False,
        mtu: int = 1522,
        sudo: bool = False,
        **kwargs: dict,
    ):
        interfaces_names = [ifc.name for ifc in interfaces]
        settings = IpfixprobeDpdkSettings(devices=interfaces_names, **kwargs)
        self._mtu = mtu
        super().__init__(executor, target, protocols, interfaces, verbose, settings, sudo)

    def _prepare_cmd(self, target: ProbeTarget, protocols: List[str], settings: IpfixprobeSettings) -> str:
        self._check_plugin("dpdk")

        if not isinstance(settings, IpfixprobeDpdkSettings):
            raise TypeError("In IpfixprobeDpdk settings should be IpfixprobeDpdkSettings.")

        args = ["ipfixprobe"]

        eal_params = []
        if settings.lcores:
            eal_params += ["--lcores", settings.lcores]
        if settings.memory:
            eal_params += ["-m", str(settings.memory)]
        if settings.file_prefix:
            eal_params += ["--file-prefix", settings.file_prefix]

        for dev in settings.devices:
            eal_params += ["-a", dev]
        ports = ",".join(str(i) for i in range(len(settings.devices)))

        dpdk_params = [f"p={ports}"]
        dpdk_params.append(f"q={settings.queues_count}")
        if settings.mbuf_size:
            dpdk_params.append(f"b={settings.mbuf_size}")
        if settings.mempool_size:
            dpdk_params.append(f"m={settings.mempool_size}")
        dpdk_params.append(f"M={self._mtu}")
        eal_params_str = " ".join(eal_params)
        dpdk_params.append(f"e={eal_params_str}")

        args += self._get_plugin_arg(IpfixprobePluginType.INPUT, "dpdk", dpdk_params)

        for _ in range(settings.queues_count - 1):
            args += self._get_plugin_arg(IpfixprobePluginType.INPUT, "dpdk", [])

        args += self._get_common_args(target, protocols, settings)
        return " ".join(args)


class IpfixprobeNdp(Ipfixprobe):
    """Implementation of Ipfixprobe connector with ndp traffic capturing."""

    def __init__(
        self,
        executor: Executor,
        target: ProbeTarget,
        protocols: List[str],
        interfaces: List[InterfaceCfg],
        verbose: bool = False,
        mtu: int = 1522,
        sudo: bool = False,
        **kwargs: dict,
    ):
        interfaces_names = [ifc.name for ifc in interfaces]
        settings = IpfixprobeNdpSettings(devices=interfaces_names, **kwargs)
        super().__init__(executor, target, protocols, interfaces, verbose, settings, sudo)
        self._mtu = mtu

    def _prepare_cmd(self, target: ProbeTarget, protocols: List[str], settings: IpfixprobeSettings) -> str:
        self._check_plugin("ndp")

        if not isinstance(settings, IpfixprobeNdpSettings):
            raise TypeError("In IpfixprobeNdp settings should be IpfixprobeNdpSettings.")

        args = ["ipfixprobe"]

        for dev_index, dev in enumerate(settings.devices):
            mask = [int(bit) for bit in f"{settings.dma_channels_map[dev_index]:b}"[::-1]]
            for i, bit in enumerate(mask):
                if bit == 1:
                    ndp_params = [f"dev={dev}:{i}"]
                    args += self._get_plugin_arg(IpfixprobePluginType.INPUT, "ndp", ndp_params)

        args += self._get_common_args(target, protocols, settings)
        return " ".join(args)

    def _before_start(self):
        for ifc in self._ifc_names.split(","):
            Tool(f"nfb-eth -d {ifc} -L {self._mtu}", executor=self._executor).run()
