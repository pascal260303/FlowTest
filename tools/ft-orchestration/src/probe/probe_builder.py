"""
Author(s): Jan Sobol <sobol@cesnet.cz>

Copyright: (C) 2022 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

Builder for creating a probe instance based on a static configuration.
"""

from os import path
from typing import Any, Dict, List, Optional

from lbr_testsuite.topology import Device
from src.common.builder_base import BuilderBase, BuilderError
from src.config.common import InterfaceCfg
from src.config.config import Config
from src.config.probe import ProbeCfg
from src.config.whitelist import WhitelistCfg
from src.probe.interface import ProbeInterface
from src.probe.probe_target import ProbeTarget

PROBE_IMPORT_PATH = path.dirname(path.realpath(__file__))


class ProbeBuilder(BuilderBase, Device):
    """Builder for creating a probe instance based on a static configuration.
    Probe class is dynamically imported from module in 'probe' directory."""

    def __init__(
        self,
        config: Config,
        disable_ansible: bool,
        extra_import_paths: List[str],
        alias: str,
        target: ProbeTarget,
        enabled_interfaces: List[str],
        cmd_connector_args: Dict[str, Any],
    ) -> None:
        """Create probe instance from static configuration by alias identifier.

        Parameters
        ----------
        config : Config
            Static configuration object.
        disable_ansible: bool
            If True, ansible preparation (with ansible_playbook_role) is disabled.
        extra_import_paths: List[str]
            Extra paths from which connectors are imported.
        alias : str
            Unique identifier in static configuration.
        target : ProbeTarget
            Export target passed to probe constructor.
        enabled_interfaces : List[str]
            Network interfaces where the exporting process should be initiated.
        cmd_connector_args : Dict[str, Any]
            Additional settings passed to connector.

        Raises
        ------
        BuilderError
            Raised when type of probe from static configuration not found in python modules.
            Or alias does not exist in configuration.
        """

        super().__init__(config, disable_ansible)  # pylint: disable=too-many-function-args

        if alias not in self._config.probes:
            raise BuilderError(f"Probe '{alias}' not found in probes configuration.")
        probe_cfg = self._config.probes[alias]

        self._prepare_env(probe_cfg)

        self._target = target
        self._interfaces = self._load_interfaces(probe_cfg, enabled_interfaces)
        self._connector_args = probe_cfg.connector if probe_cfg.connector else {}

        if probe_cfg.tests_whitelist:
            self._whitelist = config.whitelists[probe_cfg.tests_whitelist]
        else:
            self._whitelist = None

        self._protocols = probe_cfg.protocols
        self._biflow_export = probe_cfg.biflow_export

        # cmd additional arguments has higher priority, update arguments from config
        self._connector_args.update(cmd_connector_args)

        import_paths = extra_import_paths + [PROBE_IMPORT_PATH]
        self._class = self._find_class(import_paths, probe_cfg.type, ProbeInterface)

    # pylint: disable=arguments-differ
    def get(self, protocols: list[str], mtu: Optional[int] = None, **kwargs) -> ProbeInterface:
        """Create probe instance from static configuration by alias identifier.

        Parameters
        ----------
        protocols : list[str]
            List of the networking protocols which the probe should parse and export.
        mtu : int, optional
            The maximum transmission unit to be set at the probe input.
            If None, default value of connector is used.
        kwargs: dict
            Custom arguments passed to the init function of the probe

        Returns
        -------
        ProbeInterface
            New probe instance.
        """

        additional_args = {**self._connector_args, **kwargs}
        if mtu is not None:
            additional_args.update({"mtu": mtu})
            
        protocols = list(set(protocols) & set(self.get_supported_protocols()))

        return self._class(self._executor, self._target, protocols, self._interfaces, **additional_args)

    def get_enabled_interfaces(self) -> List[InterfaceCfg]:
        """Get list of enabled interfaces.

        Returns
        -------
        List[InterfaceCfg]
            Enabled interfaces.
        """

        return self._interfaces

    def get_tests_whitelist(self) -> Optional[WhitelistCfg]:
        """Get whitelist with expected failure tests.

        Returns
        -------
        WhitelistCfg, optional
            Whitelist with expected failure tests if specified in probe configuration.
        """

        return self._whitelist

    def get_supported_protocols(self) -> list[str]:
        """Get list of protocols (plugins) supported by probe. From static configuration.

        Returns
        -------
        list[str]
            List of protocol names.
        """

        return self._protocols

    def get_biflow_export(self) -> bool:
        """Find out if the probe exports biflows.

        Returns
        -------
        bool
            True when probe exports biflows, False when exports single flows.
        """

        return self._biflow_export

    @staticmethod
    def _load_interfaces(probe_cfg: ProbeCfg, enabled_interfaces: List[str]) -> List[InterfaceCfg]:
        """Check and convert string interfaces from cmd argument to InterfaceCfg form.

        Parameters
        ----------
        probe_cfg : ProbeCfg
            Probe static configuration.
        enabled_interfaces : List[str]
            Interfaces from test cmd argument.

        Returns
        -------
        List[InterfaceCfg]
            Converted interfaces.

        Raises
        ------
        BuilderError
            When interface is not supported by probe.
        """

        if len(enabled_interfaces) == 0:
            return probe_cfg.interfaces

        interfaces = []
        for ifc in enabled_interfaces:
            found = False
            for ifc_cfg in probe_cfg.interfaces:
                if ifc_cfg.name == ifc:
                    interfaces.append(ifc_cfg)
                    found = True
                    break

            if not found:
                raise BuilderError(f"Interface '{ifc}' is not supported by probe '{probe_cfg.alias}'.")

        return interfaces
