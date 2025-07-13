from abc import ABC
from dataclasses import dataclass
from typing import List, Optional
from src.common.typed_dataclass import typed_dataclass
from src.config.common import InterfaceCfg
from src.probe.interface import ProbeInterface
from lbr_testsuite.executable import (
    Executor,
)
from src.probe.probe_target import ProbeTarget

SETTINGS_TO_CONFIG = {"inactive_timeout": "idle_timeout"}


@typed_dataclass
@dataclass
class YafSettings(ABC):
    @typed_dataclass
    @dataclass
    class InputOptions(ABC):
        inf: Optional[str] = None
        type: Optional[str] = None
        export_interface: Optional[str] = None
        file: Optional[str] = None
        noerror: Optional[str] = None
        force_read_all: Optional[str] = None

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
        udp_temp_timeout: Optional[str] = None

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

    decode = Optional[DecodeOptions] = None

    vxlan_ports = Optional[set[int]] = None

    geneve_ports = Optional[set[int]] = None

    @typed_dataclass
    @dataclass
    class ExportOptions(ABC):
        silk: Optional[bool] = None
        uniflow: Optional[bool] = None
        force_ip6: Optional[bool] = None
        flow_stats: Optional[bool] = None
        delta: Optional[bool] = None
        mac: Optional[bool] = None
        mac: Optional[bool] = None
        metadata: Optional[bool] = None

    time_elements: Optional[int | str] = (
        1  # 1 = milliseconds, 2 = microseconds, 3 = nanoseconds
    )

    active_timeout: int = 300
    inactive_timeout: int = 50

    filter: Optional[str] = None

    # APPLICATION LABELING OPTIONS
    applabel: Optional[bool] = None
    applabel_rules: Optional[str] = None

    maxpayload: Optional[int] = None
    maxexport: Optional[int] = None
    export_payload: Optional[bool] = None
    export_payload_applabels: Optional[str] = None
    udp_payload: Optional[bool] = None
    stats: Optional[str] = None
    no_tombstone: Optional[bool] = None
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

    tls = Optional[TLSOptions] = None

    @typed_dataclass
    @dataclass
    class LoggingOptions(ABC):
        spec: Optional[str] = None
        level: Optional[str] = None

    log = Optional[LoggingOptions] = None


class Yaf(ProbeInterface):
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
        kwargs["decode"] = (
            YafSettings.DecodeOptions(**(kwargs.get("decode")))
            if "decode" in kwargs and kwargs["decode"]
            else None
        )
        kwargs["export"] = (
            YafSettings.ExportOptions(**(kwargs.get("export")))
            if "export" in kwargs and kwargs["export"]
            else None
        )
        kwargs["plugin"] = (
            {YafSettings.PluginOptions(**plopt) for plopt in kwargs.get("plugin")}
            if "plugin" in kwargs and kwargs["plugin"]
            else None
        )
        kwargs["pcap"] = (
            YafSettings.PCAPOptions(**(kwargs.get("pcap")))
            if "pcap" in kwargs and kwargs["pcap"]
            else None
        )
        kwargs["tls"] = (
            YafSettings.TLSOptions(**(kwargs.get("tls")))
            if "tls" in kwargs and kwargs["tls"]
            else None
        )
        kwargs["log"] = (
            YafSettings.LoggingOptions(**(kwargs.get("log")))
            if "log" in kwargs and kwargs["log"]
            else None
        )
        self._settings = YafSettings(**kwargs)
