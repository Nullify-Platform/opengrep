from types import SimpleNamespace

import pytest

from semgrep.core_runner import CoreRunner
from semgrep.engine import EngineType
from semgrep.rule import Rule
from semgrep.run_scan import run_rules
from semgrep.target_manager import SAST_PRODUCT
from semgrep.target_manager import TargetManager
from semgrep.target_mode import TargetModeConfig


def make_rule() -> Rule:
    return Rule(
        {
            "id": "test.rule",
            "pattern": "sink(...)",
            "languages": ["python"],
            "message": "test",
            "severity": "INFO",
        }
    )


@pytest.mark.quick
def test_plan_core_run_reuses_bundle_from_memory(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("print('hello')\n")
    target_manager = TargetManager([str(tmp_path)])
    rules = [make_rule()]

    original_get_files_for_rule = TargetManager.get_files_for_rule
    get_files_for_rule_calls = 0

    def counting_get_files_for_rule(self, *args, **kwargs):
        nonlocal get_files_for_rule_calls
        get_files_for_rule_calls += 1
        return original_get_files_for_rule(self, *args, **kwargs)

    monkeypatch.setattr(TargetManager, "get_files_for_rule", counting_get_files_for_rule)

    first_plan = CoreRunner.plan_core_run(
        rules,
        target_manager,
        sca_subprojects={},
    )
    second_plan = CoreRunner.plan_core_run(
        rules,
        target_manager,
        sca_subprojects={},
    )

    assert first_plan.target_mappings == second_plan.target_mappings
    assert get_files_for_rule_calls == 1


@pytest.mark.quick
def test_plan_core_run_cache_key_includes_explicit_file_bypass(tmp_path):
    app_file = tmp_path / "app.py"
    app_file.write_text("print('hello')\n")
    target_manager = TargetManager(
        [str(app_file)],
        excludes={SAST_PRODUCT: ["app.py"]},
    )
    rules = [make_rule()]

    plan_with_bypass = CoreRunner.plan_core_run(
        rules,
        target_manager,
        sca_subprojects={},
        bypass_includes_excludes_for_files=True,
    )
    plan_without_bypass = CoreRunner.plan_core_run(
        rules,
        target_manager,
        sca_subprojects={},
        bypass_includes_excludes_for_files=False,
    )

    assert plan_with_bypass.num_targets == 1
    assert plan_without_bypass.num_targets == 0


@pytest.mark.quick
def test_run_rules_reuses_pre_scan_bundle_for_interfile_scan(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("print('hello')\n")
    target_manager = TargetManager([str(tmp_path)])
    rules = [make_rule()]

    original_get_files_for_rule = TargetManager.get_files_for_rule
    get_files_for_rule_calls = 0

    def counting_get_files_for_rule(self, *args, **kwargs):
        nonlocal get_files_for_rule_calls
        get_files_for_rule_calls += 1
        return original_get_files_for_rule(self, *args, **kwargs)

    monkeypatch.setattr(TargetManager, "get_files_for_rule", counting_get_files_for_rule)

    def fake_print_scan_status(
        rules,
        target_manager,
        target_mode_config,
        sca_subprojects,
        dependency_parser_errors,
        *,
        bypass_includes_excludes_for_files=True,
        **_,
    ):
        del target_mode_config, dependency_parser_errors
        return [
            CoreRunner.plan_core_run(
                list(rules),
                target_manager,
                sca_subprojects=sca_subprojects,
                bypass_includes_excludes_for_files=bypass_includes_excludes_for_files,
            )
        ]

    monkeypatch.setattr(
        "semgrep.scan_report.print_scan_status",
        fake_print_scan_status,
    )

    class FakeCoreRunner:
        def invoke_semgrep_core(
            self,
            target_manager,
            rules,
            _dump_command_for_core,
            _time_flag,
            _matching_explanations,
            _engine_type,
            _strict,
            _run_secrets,
            _disable_secrets_validation,
            target_mode_config,
            resolved_subprojects,
            *,
            bypass_includes_excludes_for_files=True,
            **_,
        ):
            assert not target_mode_config.is_pro_diff_scan
            plan = CoreRunner.plan_core_run(
                list(rules),
                target_manager,
                sca_subprojects=resolved_subprojects,
                bypass_includes_excludes_for_files=bypass_includes_excludes_for_files,
            )
            assert plan.num_targets == 1
            return {}, [], SimpleNamespace()

    run_rules(
        rules,
        target_manager,
        FakeCoreRunner(),
        SimpleNamespace(handle_semgrep_errors=lambda errors: None),
        dump_command_for_core=False,
        time_flag=False,
        matching_explanations=False,
        engine_type=EngineType.PRO_INTERFILE,
        strict=False,
        run_secrets=False,
        disable_secrets_validation=False,
        target_mode_config=TargetModeConfig.whole_scan(),
    )

    assert get_files_for_rule_calls == 1
