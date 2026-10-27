import asyncio
import json
import sys
from types import SimpleNamespace

import agents.regression_agent as regression_module
import main as main_module
from agents.regression_agent import RegressionAgent
from agents.remediation_agent import RemediationAgent
from main import run_retest


def _finding(vuln_type="novel_runtime_risk"):
    return {
        "id": "finding-1",
        "title": "Novel runtime risk",
        "severity": "high",
        "vulnerability_type": vuln_type,
        "file_path": "app.py",
        "line_start": 10,
        "line_end": 12,
        "verification_status": "needs_evidence",
        "verification_predicate": "Untrusted input reaches a privileged sink",
        "evidence_bundle": {"items": [{"type": "source_path"}], "gaps": ["runtime pending"]},
    }


def test_unknown_finding_gets_normalized_remediation_with_both_controls():
    result = asyncio.run(RemediationAgent().run({"verified_findings": [_finding()]}))
    bundle = result.data["remediation_bundles"][0]

    assert bundle["schema"] == "vibe-sec.remediation-bundle"
    assert bundle["metadata"]["proposal_only"] is True
    assert bundle["positive_retest_cases"]
    assert bundle["negative_retest_cases"]
    assert bundle["expected_surface_change"]
    assert "runtime pending" in bundle["ai_patch_prompt"]


def test_protocol_and_workflow_findings_use_specialized_remediation_profiles():
    expected = {
        "ssrf": "input_validation",
        "unsafe_deserialization": "code_refactor",
        "workflow_insecurity": "configuration_fix",
    }
    for vulnerability_type, strategy in expected.items():
        bundle = asyncio.run(RemediationAgent().run({
            "verified_findings": [_finding(vulnerability_type)],
        })).data["remediation_bundles"][0]
        assert bundle["patch_strategy"] == strategy
        assert bundle["positive_retest_cases"]
        assert bundle["negative_retest_cases"]
        assert bundle["expected_surface_change"]


def test_regression_requires_controls_and_changed_tree(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    bundle = asyncio.run(RemediationAgent().run({"verified_findings": [_finding()]})).data["remediation_bundles"][0]
    bundle["fix_result"] = {
        "status": "fixed",
        "changed_files": ["app.py"],
        "retest_evidence": [
            {
                "control_type": "negative",
                "status": "passed",
                "predicate": "exploit blocked",
                "artifact_ref": "artifact-negative",
            },
            {
                "control_type": "positive",
                "status": "passed",
                "predicate": "valid behavior works",
                "artifact_ref": "artifact-positive",
            },
        ],
    }

    result = asyncio.run(RegressionAgent().run({
        "project_path": str(tmp_path),
        "completed_packages": [bundle],
        "run_project_tests": False,
    }))
    report = result.data["regression_reports"][0]

    assert report["overall_status"] == "partial"
    assert report["tests_passed"] == 2
    assert report["tests_skipped"] == 1


def test_regression_rejects_bare_pass_claims_and_out_of_scope_changes(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    bundle = asyncio.run(RemediationAgent().run({"verified_findings": [_finding()]})).data["remediation_bundles"][0]
    bundle["fix_result"] = {
        "status": "fixed",
        "changed_files": ["app.py", "config.py"],
        "retest_evidence": [
            {"control_type": "negative", "status": "passed", "predicate": "exploit blocked"},
            {"control_type": "positive", "status": "passed", "predicate": "valid behavior works"},
        ],
    }

    result = asyncio.run(RegressionAgent().run({
        "project_path": str(tmp_path),
        "completed_packages": [bundle],
        "run_project_tests": False,
    }))
    report = result.data["regression_reports"][0]

    assert report["overall_status"] == "failure"
    controls = next(item for item in report["test_results"] if item["test_type"] == "retest_controls")
    changed_tree = next(item for item in report["test_results"] if item["test_type"] == "changed_tree")
    assert controls["status"] == "failed"
    assert changed_tree["status"] == "failed"
    assert changed_tree["details"]["outside_allowed_scope"] == ["config.py"]


def test_run_retest_api_executes_regression_agent(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    bundle = asyncio.run(RemediationAgent().run({"verified_findings": [_finding()]})).data["remediation_bundles"][0]

    result = asyncio.run(run_retest(str(tmp_path), [bundle], run_project_tests=False))

    assert len(result["regression_reports"]) == 1
    assert result["regression_reports"][0]["overall_status"] == "partial"


def test_retest_uses_durable_tree_snapshot_when_changed_files_are_not_supplied(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("value = 1\n", encoding="utf-8")
    bundle = asyncio.run(RemediationAgent().run({
        "project_path": str(tmp_path),
        "session_id": "snapshot-test",
        "verified_findings": [_finding()],
    })).data["remediation_bundles"][0]
    app.write_text("value = 2\n", encoding="utf-8")
    bundle["fix_result"] = {
        "status": "fixed",
        "retest_evidence": [
            {
                "control_type": "negative",
                "status": "passed",
                "predicate": "exploit blocked",
                "artifact_ref": "artifact-negative",
            },
            {
                "control_type": "positive",
                "status": "passed",
                "predicate": "valid behavior works",
                "artifact_ref": "artifact-positive",
            },
        ],
    }

    result = asyncio.run(run_retest(str(tmp_path), [bundle], run_project_tests=False))
    changed_tree = next(
        item for item in result["regression_reports"][0]["test_results"]
        if item["test_type"] == "changed_tree"
    )

    assert changed_tree["status"] == "passed"
    assert changed_tree["details"]["changed_source"] == "tree_snapshot"
    assert changed_tree["details"]["snapshot_diff"]["modified_files"] == ["app.py"]


def test_project_tests_execute_only_through_isolated_container(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    bundle = asyncio.run(RemediationAgent().run({
        "verified_findings": [_finding()],
    })).data["remediation_bundles"][0]
    bundle["fix_result"] = {"status": "fixed", "changed_files": ["app.py"]}
    calls = []

    class FakeDockerExecutor:
        def __init__(self, **kwargs):
            calls.append(("init", kwargs))

        async def execute_command(self, command, **kwargs):
            calls.append(("execute", command, kwargs))
            return SimpleNamespace(
                status="completed", exit_code=0, stdout="1 passed", stderr="", error=None,
            )

    monkeypatch.setattr(regression_module, "DockerExecutor", FakeDockerExecutor)
    monkeypatch.setattr(
        regression_module.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("host subprocess must not run")),
    )

    result = asyncio.run(RegressionAgent().run({
        "project_path": str(tmp_path),
        "completed_packages": [bundle],
        "run_project_tests": True,
        "test_command": ["python", "-m", "pytest", "-q"],
    }))
    project_test = next(
        item for item in result.data["regression_reports"][0]["test_results"]
        if item["test_type"] == "project_tests"
    )

    assert project_test["status"] == "passed"
    assert calls[0] == ("init", {
        "image": "python:3.12-slim", "network_disabled": True,
        "memory_limit": "1g", "cpu_limit": "1.0",
    })
    assert calls[1][2]["project_path"] == str(tmp_path)
    assert project_test["details"]["network"] == "none"
    assert project_test["details"]["workspace"] == "read_only"


def test_python_project_tests_can_use_a_prepared_process_local_image(monkeypatch):
    monkeypatch.setenv("VIBE_SEC_PYTHON_TEST_IMAGE", "vibe-sec-python-flask:3.1.3")

    assert RegressionAgent._test_image(["python", "-m", "unittest"]) == "vibe-sec-python-flask:3.1.3"


def test_node_project_tests_can_use_a_prepared_process_local_image(monkeypatch):
    monkeypatch.setenv("VIBE_SEC_NODE_TEST_IMAGE", "vibe-sec-juice-runtime:node24")

    assert RegressionAgent._test_image(["node", "--test"]) == "vibe-sec-juice-runtime:node24"
    assert RegressionAgent._test_image(["npm", "test"]) == "vibe-sec-juice-runtime:node24"


def test_retest_cli_accepts_utf8_bom_input(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "retest-input.json"
    input_path.write_text(json.dumps({"remediation_bundles": []}), encoding="utf-8-sig")

    async def fake_run_retest(*args, **kwargs):
        return {"regression_reports": []}

    monkeypatch.setattr(main_module, "run_retest", fake_run_retest)
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "retest", str(tmp_path), "--input", str(input_path), "--skip-project-tests"],
    )

    main_module.main()

    assert json.loads(capsys.readouterr().out) == {"regression_reports": []}
