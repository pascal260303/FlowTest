import os

import pytest
import time
from lbr_testsuite.topology.topology import select_topologies
from src.collector.collector_builder import CollectorBuilder
from src.common.html_report_plugin import HTMLReportData
from src.common.utils import (
    collect_scenarios,
    download_logs,
    get_project_root,
)
from src.config.scenario import SimulationScenario
from src.generator.generator_builder import GeneratorBuilder
from src.generator.interface import MultiplierSpeed
from src.probe.probe_builder import ProbeBuilder
from tests.simulation.test_simulation_general import setup_replicator, validate

PROJECT_ROOT = get_project_root()
CUSTOM_TESTS_DIR = os.path.join(PROJECT_ROOT, "testing/custom")
select_topologies(["replicator"])

DEFAULT_REPLICATOR_PREFIX = 8

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
    generator_conf.max_flow_inter_packet_gap = int(inactive_t * 0.8)

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

    time.sleep(15)

    probe_instance.stop()
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
        start_time=stats.start_time,
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
