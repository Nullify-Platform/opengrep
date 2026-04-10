from pathlib import Path

import pytest

import semgrep.semgrep_interfaces.semgrep_output_v1 as out
from semgrep.core_runner import CoreRunner
from semgrep.core_targets_plan import Plan
from semgrep.core_targets_plan import Task
from semgrep.engine import EngineType
from semgrep.rule import Rule
from semgrep.run_scan import get_reusable_interfile_scan_plan
from semgrep.run_scan import run_rules
from semgrep.target_mode import TargetModeConfig


def make_rule(rule_id: str) -> Rule:
    return Rule(
        {
            "id": rule_id,
            "languages": ["python"],
            "message": "test message",
            "severity": "INFO",
            "pattern": "print(...)",
        }
    )


def make_sast_plan(rule: Rule, path: str = "foo.py") -> Plan:
    return Plan(
        [
            Task(
                path=path,
                analyzer=rule.languages[0],
                products=(out.Product(out.SAST()),),
                rule_nums=(0,),
            )
        ],
        [rule],
        product=out.Product(out.SAST()),
        sca_subprojects={},
    )


@pytest.mark.quick
def test_get_reusable_interfile_scan_plan_returns_matching_sast_plan() -> None:
    rule = make_rule("rule.matching")
    sast_plan = make_sast_plan(rule)

    reusable_plan = get_reusable_interfile_scan_plan(
        EngineType.PRO_INTERFILE,
        TargetModeConfig.whole_scan(),
        [rule],
        [sast_plan],
    )

    assert reusable_plan is sast_plan


@pytest.mark.quick
def test_get_reusable_interfile_scan_plan_rejects_diff_scans_and_rule_mismatches() -> None:
    matching_rule = make_rule("rule.matching")
    other_rule = make_rule("rule.other")
    sast_plan = make_sast_plan(matching_rule)

    diff_plan = get_reusable_interfile_scan_plan(
        EngineType.PRO_INTERFILE,
        TargetModeConfig.pro_diff_scan(frozenset({Path("foo.py")}), diff_depth=2),
        [matching_rule],
        [sast_plan],
    )
    mismatch_plan = get_reusable_interfile_scan_plan(
        EngineType.PRO_INTERFILE,
        TargetModeConfig.whole_scan(),
        [other_rule],
        [sast_plan],
    )

    assert diff_plan is None
    assert mismatch_plan is None


@pytest.mark.quick
def test_run_rules_passes_reusable_interfile_plan_to_core_runner(mocker) -> None:
    rule = make_rule("rule.matching")
    sast_plan = make_sast_plan(rule)
    sca_plan = Plan([], [], product=out.Product(out.SCA()), sca_subprojects={})
    mock_output_extra = mocker.Mock()
    mock_output_extra.all_targets = set()

    core_runner = mocker.Mock()
    core_runner.invoke_semgrep_core.return_value = ({}, [], mock_output_extra)
    output_handler = mocker.Mock()
    target_manager = mocker.Mock()

    mocker.patch(
        "semgrep.run_scan.scan_report.print_scan_status",
        return_value=[sast_plan, sca_plan],
    )

    run_rules(
        [rule],
        target_manager,
        core_runner,
        output_handler,
        dump_command_for_core=False,
        time_flag=False,
        matching_explanations=False,
        engine_type=EngineType.PRO_INTERFILE,
        strict=False,
        target_mode_config=TargetModeConfig.whole_scan(),
    )

    assert (
        core_runner.invoke_semgrep_core.call_args.kwargs["precomputed_plan"]
        is sast_plan
    )


@pytest.mark.quick
def test_core_runner_uses_precomputed_plan_without_replanning(mocker, tmp_path) -> None:
    rule = make_rule("rule.matching")
    precomputed_plan = make_sast_plan(rule)
    mock_state = mocker.Mock()
    mock_state.env.user_data_folder = tmp_path
    mock_state.get_cli_ux_flavor.return_value = object()
    mock_state.metrics = mocker.Mock()
    mock_state.terminal.is_debug = False

    mocker.patch("semgrep.core_runner.get_state", return_value=mock_state)
    mocker.patch(
        "semgrep.engine.EngineType.get_binary_path",
        return_value=Path("/tmp/opengrep-core"),
    )
    mocker.patch.object(
        CoreRunner,
        "plan_core_run",
        side_effect=AssertionError("plan_core_run should not be called"),
    )

    runner = CoreRunner(
        jobs=1,
        engine_type=EngineType.OSS,
        timeout=1,
        max_memory=0,
        timeout_threshold=0,
        interfile_timeout=0,
        capture_stderr=False,
        optimizations="none",
        allow_untrusted_validators=False,
    )

    with pytest.raises(SystemExit) as excinfo:
        runner._run_rules_direct_to_semgrep_core_helper(
            [rule],
            mocker.Mock(),
            dump_command_for_core=True,
            time_flag=False,
            matching_explanations=False,
            engine=EngineType.OSS,
            strict=False,
            run_secrets=False,
            disable_secrets_validation=False,
            target_mode_config=TargetModeConfig.whole_scan(),
            sca_subprojects={},
            opengrep_ignore_pattern=None,
            precomputed_plan=precomputed_plan,
        )

    assert excinfo.value.code == 0
