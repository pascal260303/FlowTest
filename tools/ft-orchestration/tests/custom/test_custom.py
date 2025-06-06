import ipaddress
import logging
import os
import time
from typing import Optional

import pandas as pd
import pytest
from ftanalyzer.models.precise_model import PreciseModel
from ftanalyzer.models.sm_data_types import (
    SMMetric,
    SMMetricType,
    SMRule,
    SMSubnetSegment,
)
from ftanalyzer.models.statistical_model import StatisticalModel
from ftanalyzer.replicator.flow_replicator import FlowReplicator
from ftanalyzer.reports.precise_report import PreciseReport
from ftanalyzer.reports.statistical_report import StatisticalReport
from lbr_testsuite.topology.topology import select_topologies
from src.collector.collector_builder import CollectorBuilder
from src.common.html_report_plugin import HTMLReportData
from src.common.utils import (
    collect_scenarios,
    download_logs,
    get_project_root,
    get_replicator_prefix,
    ip_network_add_offset,
)
from src.config.scenario import AnalysisCfg, SimulationScenario
from src.generator.ft_generator import FtGeneratorConfig
from src.generator.generator_builder import GeneratorBuilder
from src.generator.interface import GeneratorStats, MultiplierSpeed, Replicator
from src.probe.probe_builder import ProbeBuilder

PROJECT_ROOT = get_project_root()
CUSTOM_TESTS_DIR = os.path.join(PROJECT_ROOT, "testing/custom")
select_topologies(["replicator"])

DEFAULT_REPLICATOR_PREFIX = 8

def validate(
    analysis: AnalysisCfg,
    prefilter_conf: list[str],
    flows_file: str,
    reference: pd.DataFrame,
    active_timeout: int,
    stats: GeneratorStats,
    biflows: bool,
) -> tuple[StatisticalReport, Optional[PreciseReport]]:
    """Perform statistical and/or precise model evaluation of the test scenario.

    Parameters
    ----------
    analysis: AnalysisCfg
        Object describing how the test results should be evaluated.
    prefilter_conf: list[str]
        Prefilter IP ranges.
    flows_file: str
        Path to a file with flows from collector.
    reference: pd.DataFrame
        Reference flows in DataFrame.
    active_timeout: int
        Active timeout which was used during flow creation process by the probe.
    start_time: int
        Timestamp of the first packet.
    biflows: bool
        Probe exports biflows.

    Returns
    -------
    tuple
        Reports from the evaluation. Statistical report is always present,
        precise report is present only if a precise model is selected.
    """

    if analysis.model == "precise":
        model = PreciseModel(flows_file, reference, active_timeout, stats, biflows)
        if len(prefilter_conf) > 0:
            precise_report = model.validate_precise(
                [SMSubnetSegment(subnet, bidir=True) for subnet in prefilter_conf],
                check_complement=True,
            )
        else:
            precise_report = model.validate_precise()

        # precise model always expects zero faults
        metrics = [
            SMMetric(SMMetricType.PACKETS, 0),
            SMMetric(SMMetricType.BYTES, 0),
            SMMetric(SMMetricType.FLOWS, 0),
            SMMetric(SMMetricType.PPS, 0),
            SMMetric(SMMetricType.MBPS, 0),
            SMMetric(SMMetricType.DURATION, 0),
        ]
    else:
        model = StatisticalModel(flows_file, reference, stats)
        precise_report = None
        metrics = analysis.metrics

    if len(prefilter_conf) > 0:
        rules = [SMRule(metrics, SMSubnetSegment(subnet, bidir=True)) for subnet in prefilter_conf]
        check_complement = True
    else:
        rules = [SMRule(metrics)]
        check_complement = False

    stats_report = model.validate(rules, check_complement)

    return stats_report, precise_report


def setup_replicator(
    generator: Replicator,
    conf: FtGeneratorConfig,
    prefilter_conf: list[str],
    loop_cnt: int,
    unit_cnt: int,
) -> tuple[FlowReplicator, list[str]]:
    """
    Setup replicator units and loops so that there is enough bits in an IP prefix
    to perform replication in a way that IP subnets do not overlap.

    Parameters
    ----------
    generator: Replicator
        Generator instance.
    conf: FtGeneratorConfig
        Generator configuration.
    prefilter_conf: list[str]
        Prefilter IP ranges.
    loop_cnt: int
        Number of traffic replay loops.
    unit_cnt: int
        Number of replication units.

    Returns
    -------
    (FlowReplicator, list[str])
        Flow replicator object to adjust reference flows report form the packet player.
        List of strings with extended prefilter IP ranges. Scaled to match replication
        units and loops.
    """

    assert loop_cnt > 0 and unit_cnt > 0

    prefix = get_replicator_prefix(
        (loop_cnt * unit_cnt - 1).bit_length(), DEFAULT_REPLICATOR_PREFIX, conf.ipv4.ip_range, conf.ipv6.ip_range
    )
    if conf.ipv4.ip_range is None:
        conf.ipv4.ip_range = f"{ipaddress.IPv4Address(2 ** (32 - prefix)):s}/{prefix}"

    if conf.ipv6.ip_range is None:
        conf.ipv6.ip_range = f"{ipaddress.IPv6Address(2 ** (128 - prefix)):s}/{prefix}"

    extended_prefilter_conf = set()

    for unit_n in range(unit_cnt):
        offset = unit_n * 2 ** (32 - prefix)
        generator.add_replication_unit(
            srcip=Replicator.AddConstant(offset),
            dstip=Replicator.AddConstant(offset),
        )
        for subnet in prefilter_conf:
            extended_prefilter_conf.add(ip_network_add_offset(subnet, offset))

    loop_offset = unit_cnt * 2 ** (32 - prefix)
    generator.set_loop_modifiers(srcip_offset=loop_offset, dstip_offset=loop_offset)
    extended_prefilter_conf = {
        ip_network_add_offset(subnet, loop_n * loop_offset)
        for subnet in extended_prefilter_conf
        for loop_n in range(loop_cnt)
    }

    logging.getLogger().info("Generator - ipv4 range: %s, ipv6 range: %s", conf.ipv4.ip_range, conf.ipv6.ip_range)
    logging.getLogger().info("Replicator - units: %d, loops: %d, prefix: %d", unit_cnt, loop_cnt, prefix)

    return FlowReplicator(generator.get_replicator_config()), list(map(str, extended_prefilter_conf))

@pytest.mark.custom
@pytest.mark.parametrize(
    "scenario, test_id",
    collect_scenarios(CUSTOM_TESTS_DIR, SimulationScenario, name="sim_general"),
)
# pylint: disable=too-many-locals
# pylint: disable=unused-argument
def test_custom(
    request: pytest.FixtureRequest,
    generator: GeneratorBuilder,
    device: ProbeBuilder,
    analyzer: CollectorBuilder,
    scenario: SimulationScenario,
    test_id: str,
    log_dir: str,
    tmp_dir: str,
    check_requirements,
):
    """Test with ability of replication original traffic from network profile.
    Replication units are used for sampled profiles to achieve original amount
    of traffic. Traffic could be replayed in more non-overlapping loops.
    Statistical model is used for evaluation of the test.

    Parameters
    ----------
    request : pytest.FixtureRequest
        Pytest request object.
    generator: GeneratorBuilder
        Traffic generator builder.
    device: ProbeBuilder
        Tested probe builder.
    analyzer: CollectorBuilder
        Collector builder.
    scenario: SimulationScenario
        Scenario configration.
    test_id: str
        Path to scenario filename.
    log_dir: str
        Directory for storing logs.
    tmp_dir: str
        Temporary directory which can be used for the duration of the testing scenario.
        Removed after the scenario test is concluded.
    check_requirements: fixture
        Function which automatically checks whether the scenario can be started
        with selected generator / probe configuration.
    """

    objects_to_cleanup = []

    def cleanup():
        for obj in objects_to_cleanup:
            obj.stop()
            obj.cleanup()

    probe_instance, collector_instance, generator_instance = (None, None, None)

    def finalizer_download_logs():
        download_logs(
            log_dir,
            collector=collector_instance,
            generator=generator_instance,
            probe=probe_instance,
        )

    request.addfinalizer(cleanup)
    request.addfinalizer(finalizer_download_logs)

    # initialize collector
    collector_instance = analyzer.get()
    objects_to_cleanup.append(collector_instance)
    collector_instance.start()

    # initialize probe
    probe_conf = scenario.test.get_probe_conf(
        device.get_instance_type(), scenario.default.probe
    )
    probe_instance = device.get(mtu=scenario.mtu, **probe_conf)
    objects_to_cleanup.append(probe_instance)
    active_t, inactive_t = probe_instance.get_timeouts()

    # initialize generator
    generator_conf = scenario.test.get_generator_conf(scenario.default.generator)
    generator_instance = generator.get(scenario.mtu)
    # file to save replication report from ft-generator (flows reference)
    ref_file = os.path.join(tmp_dir, "report.csv")

    # set max inter packet gap in a profile slightly below configured probe's inactive timeout
    generator_conf.max_flow_inter_packet_gap = int(inactive_t * 2/3)

    # setup replicator
    flow_replicator, prefilter_conf = setup_replicator(
        generator_instance,
        generator_conf,
        scenario.test.get_prefilter_conf(scenario.default),
        scenario.test.loops,
        scenario.test.get_replicator_units(scenario.sampling),
    )
    if len(prefilter_conf) > 0:
        probe_instance.set_prefilter(prefilter_conf)

    # determine replay speed and verify that only MultiplierSpeed is used if precise evaluation model is selected
    speed = scenario.test.get_replay_speed(scenario.default)
    if scenario.test.analysis.model == "precise":
        assert isinstance(speed, MultiplierSpeed)

    # start probe instance after prefilter is set up
    probe_instance.start()

    # start_profile is asynchronous
    generator_instance.start_profile(
        scenario.get_profile(scenario.filename, CUSTOM_TESTS_DIR),
        ref_file,
        speed=speed,
        loop_count=scenario.test.loops,
        generator_config=generator_conf,
    )

    # method stats blocks until traffic is sent
    stats = generator_instance.stats()

    time.sleep(5)

    probe_instance.stop()
    
    time.sleep(5)
    collector_instance.stop()

    flows_file = os.path.join(tmp_dir, "flows.csv")
    collector_instance.get_reader().save_csv(flows_file)

    replicated_ref = flow_replicator.replicate(
        input_file=ref_file,
        loops=scenario.test.loops,
        speed_multiplier=speed.speed if isinstance(speed, MultiplierSpeed) else 1.0,
    )

    stats_report, precise_report = validate(
        analysis=scenario.test.analysis,
        prefilter_conf=prefilter_conf,
        flows_file=flows_file,
        reference=replicated_ref,
        active_timeout=active_t,
        stats=stats,
        biflows=device.get_biflow_export(),
    )

    print("")
    stats_report.print_results()
    if precise_report is not None:
        precise_report.print_results()

    HTMLReportData.simulation_summary_report.update_stats(
        "sim_general",
        stats_report.is_passing()
        and (not precise_report or precise_report.is_passing()),
    )

    if not stats_report.is_passing() or (
        precise_report is not None and not precise_report.is_passing()
    ):
        assert False, (
            f"evaluation of test: {request.function.__name__}[{test_id}] failed"
        )
