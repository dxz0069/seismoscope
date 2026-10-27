"""Baseline end-to-end audit tests for the fixture project."""

import asyncio
import json
import sys
from functools import lru_cache
from pathlib import Path
from unittest.mock import patch

import pytest

import main as main_module
from core.runtime.docker_executor import DockerExecutor
from main import format_result, run_audit, run_skill_audit

FIXTURE_PROJECT = Path(__file__).parent / "fixtures"

@lru_cache(maxsize=1)
def run_fixture_audit():
    # This deterministic fixture does not exercise container adapters.
    with patch.object(DockerExecutor, "_check_docker", return_value=False):
        return asyncio.run(
            run_audit(
                project_path=str(FIXTURE_PROJECT),
                output_format="markdown",
                use_llm=False,
                verbose=False,
            )
        )


def test_basic_audit_detects_expected_fixture_findings():
    result = run_fixture_audit()

    findings = result.get("findings", [])
    vuln_types = {finding.get("vulnerability_type") for finding in findings}
    severities = {finding.get("severity") for finding in findings}

    assert result["orchestration_completed"] is True
    assert result["audit_request"] == {
        "trigger": "explicit",
        "changed_files": [],
        "scope": {
            "web_vulns": True,
            "agent_vulns": True,
            "mcp_vulns": True,
            "secret_leaks": True,
            "workflow_vulns": True,
        },
    }
    assert len(findings) >= 10
    assert "sql_injection" in vuln_types
    assert "command_injection" in vuln_types
    assert "code_injection" in vuln_types
    assert "path_traversal" in vuln_types
    assert "hardcoded_password" in vuln_types
    assert "prompt_injection" in vuln_types
    assert "excessive_agency" in vuln_types
    eval_findings = [
        finding for finding in findings
        if finding.get("file_path") == "vulnerable_app.py" and finding.get("line_start") == 81
    ]
    assert eval_findings
    assert {finding.get("vulnerability_type") for finding in eval_findings} == {"code_injection"}
    assert "critical" in severities
    assert "high" in severities
    assert all(
        finding.get("verification_status") in {"verified", "static_only", "needs_evidence", "rejected"}
        for finding in findings
    )
    assert all(
        not finding.get("evidence_bundle", {}).get("gaps")
        for finding in findings
        if finding.get("verification_status") == "verified"
    )
    assert result["audit_summary"]["needs_evidence_findings"] >= 0

    visualization = result["runtime_surface_graph"]["visualization"]
    assert visualization["schema"] == "vibe-sec.runtime-surface-visualization"
    assert visualization["nodes"]
    assert visualization["edges"]
    assert visualization["risk_paths"]
    assert result["threat_model"]["hypotheses"]
    assert result["runtime_graph_observations"]
    assert [item["phase"] for item in result["vrtm_evolution"]] == ["audit", "verification"]
    assert all(item["status"] == "updated" for item in result["vrtm_evolution"])
    assert any(
        hypothesis["status"] in {"supported", "refuted"}
        for hypothesis in result["threat_model"]["hypotheses"]
    )

    serialized = json.dumps(result, ensure_ascii=False)
    assert "sk-1234567890abcdef" not in serialized
    assert "secret123" not in serialized


def test_basic_audit_generates_remediation_and_regression_outputs():
    result = run_fixture_audit()

    findings = result.get("findings", [])
    remediation_bundles = result.get("remediation_bundles", [])
    regression_reports = result.get("regression_reports", [])

    assert remediation_bundles
    assert len(remediation_bundles) == (
        len(result["verified_findings"]) + len(result["needs_evidence_findings"])
    )
    assert len(findings) == result["verification_summary"]["total_candidates"]
    assert regression_reports == []
    assert result["verification_summary"]["conserved"] is True
    assert result["verification_summary"]["total_candidates"] == len(result["merged_findings"])

    first_bundle = remediation_bundles[0]
    assert first_bundle["finding_id"]
    assert first_bundle["ai_patch_prompt"]
    assert first_bundle["patch_constraints"]
    assert first_bundle["retest_plan"]
    assert first_bundle["acceptance_criteria"]


def test_markdown_formatter_renders_audit_report():
    result = run_fixture_audit()
    report = format_result(result, "markdown")

    assert "# Vibe Sec" in report
    assert "sql_injection" in report
    assert "command_injection" in report


def test_audit_lanes_are_parallel_child_tasks(tmp_path):
    result = asyncio.run(
        run_audit(
            project_path=str(FIXTURE_PROJECT),
            use_llm=False,
            verbose=False,
            session_dir=str(tmp_path),
        )
    )

    assert result["audit_summary"]["execution_mode"] == "parallel_lanes"
    # 计数与 tests/fixtures 植入漏洞对齐：api_key 不再被相邻 password 合并、
    # MCP 字典语法通配权限与 f-string XSS 为 v0.7.0 新增检出。
    # agent 8→5：prompt_injection 规则加污点门控后，fixture 里 3 条
    # system_prompt 提及类（类型声明/常量赋值）噪声不再报出。
    assert result["audit_lanes"] == {
        "web_audit": 6,
        "agent_audit": 5,
        "secrets_audit": 4,
        "mcp_audit": 2,
    }
    assert len(result["audit_task_ids"]) == 5
    assert len(result["audit_task_ids"]) == len(set(result["audit_task_ids"]))

    audit_checkpoints = [
        checkpoint
        for checkpoint in result["session"]["checkpoints"]
        if checkpoint["phase"] == "agent_task:audit"
    ]
    parent = next(
        checkpoint
        for checkpoint in audit_checkpoints
        if checkpoint["state"].get("reason") == "parent_dispatched"
    )
    children = parent["state"]["children"]
    assert len(children) == 5
    assert {child["metadata"]["audit_lane"] for child in children} == {
        "web_audit",
        "agent_audit",
        "mcp_audit",
        "secrets_audit",
        "workflow_audit",
    }
    assert len({child["parent_task_id"] for child in children}) == 1


def test_real_llm_mode_requires_explicit_key(monkeypatch):
    monkeypatch.delenv("VIBE_SEC_DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    with pytest.raises(ValueError, match="requires"):
        asyncio.run(run_audit(project_path=str(FIXTURE_PROJECT), use_llm=True))


def test_run_audit_rejects_missing_project_directory(tmp_path):
    with pytest.raises(ValueError, match="existing directory"):
        asyncio.run(run_audit(project_path=str(tmp_path / "missing")))


def test_skill_audit_suggest_only_returns_stable_trigger_and_changed_scope(tmp_path):
    (tmp_path / "auth.py").write_text("authorize = True\n", encoding="utf-8")

    result = asyncio.run(run_skill_audit(
        str(tmp_path), changed_files=["auth.py"], suggest_only=True,
    ))

    assert result["contract_version"] == "vibe-sec.skill-result.v2"
    assert result["audit_executed"] is False
    assert result["trigger_decision"]["mode"] == "suggest"
    assert result["trigger_decision"]["matched_paths"] == ["auth.py"]
    assert result["scope"] == {
        "mode": "changed_files_with_transitive_security_context",
        "changed_files": ["auth.py"],
    }


def test_skill_audit_rejects_changed_file_scope_escape(tmp_path):
    with pytest.raises(ValueError, match="escapes project root"):
        asyncio.run(run_skill_audit(
            str(tmp_path), changed_files=["../outside.py"], suggest_only=True,
        ))


def test_default_skill_result_stays_below_100_kib_on_full_fixture(tmp_path, monkeypatch):
    async def fixture_audit(*args, **kwargs):
        return run_fixture_audit()

    monkeypatch.setattr(main_module, "run_audit", fixture_audit)
    monkeypatch.setenv("VIBE_SEC_STATE_HOME", str(tmp_path / "state"))

    result = asyncio.run(run_skill_audit(str(FIXTURE_PROJECT)))
    payload = json.dumps(result, ensure_ascii=False, default=str).encode("utf-8")

    assert len(payload) < 100 * 1024
    assert "audit_result" not in result
    assert Path(result["full_result_ref"]["path"]).is_file()
    assert all(Path(item["detail_ref"]["path"]).is_file() for item in result["returned_packages"])


def test_audit_cli_reports_invalid_authorization_without_traceback(tmp_path, monkeypatch, capsys):
    project = tmp_path / "project"
    project.mkdir()
    missing = tmp_path / "missing-authorization.json"
    monkeypatch.setattr(sys, "argv", [
        "vibe-sec", "audit", str(project), "--authorization", str(missing),
    ])

    with pytest.raises(SystemExit) as exit_info:
        main_module.main()

    output = capsys.readouterr().out
    assert exit_info.value.code == 1
    assert output.startswith("Error: Invalid verification authorization:")
    assert "Traceback" not in output


if __name__ == "__main__":
    audit_result = run_fixture_audit()
    print(format_result(audit_result, "markdown"))
