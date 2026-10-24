import asyncio

import pytest

import agents.regression_agent as regression_module
from agents.remediation_agent import RemediationAgent
from core.agents.base import AgentResult
from core.remediation import issue_remediation_approval, load_remediation_approval
from core.session.models import RunSession
from core.session.store import SessionStore
from core.vrtm import VRTMService
from main import run_retest


def _finding():
    return {
        "id": "finding-agent-1",
        "title": "Agent has an unrestricted shell capability",
        "severity": "high",
        "vulnerability_type": "excessive_agency",
        "file_path": "agent.py",
        "line_start": 2,
        "line_end": 2,
        "verification_status": "verified",
        "verification_predicate": "A high-impact tool can run without an approval boundary",
        "evidence_bundle": {"items": [{"type": "source_path"}], "gaps": []},
    }


def _success_regression(monkeypatch):
    async def run(self, payload):
        reports = [
            {
                "package_id": package["package_id"],
                "finding_id": package["finding_id"],
                "overall_status": "success",
                "tests_run": 3,
                "tests_passed": 3,
                "tests_failed": 0,
                "tests_skipped": 0,
                "test_results": [],
            }
            for package in payload["completed_packages"]
        ]
        return AgentResult.success_result(data={"regression_reports": reports})

    monkeypatch.setattr(regression_module.RegressionAgent, "run", run)


def _prepared_session(tmp_path):
    (tmp_path / "agent.py").write_text(
        "system_prompt = 'Handle user requests'\n"
        "def shell_tool(command):\n"
        "    return os.system(command)\n",
        encoding="utf-8",
    )
    baseline = asyncio.run(VRTMService(str(tmp_path)).build(persist=True))
    hypothesis = baseline["threat_model"]["hypotheses"][0]
    bundle = asyncio.run(RemediationAgent().run({"verified_findings": [_finding()]})).data[
        "remediation_bundles"
    ][0]
    planned = {item["control_id"]: item["predicate"] for item in bundle["retest_plan"]}
    bundle.update(
        {
            "state": "completed",
            "surface_node_ids": [hypothesis["attack_path"][0]],
            "risk_hypothesis_ids": [hypothesis["id"]],
            "fix_result": {
                "status": "fixed",
                "changed_files": ["agent.py"],
                "retest_evidence": [
                    {
                        "control_type": "negative",
                        "status": "passed",
                        "control_id": "negative-exploit",
                        "predicate": planned["negative-exploit"],
                        "artifact_ref": "artifact-negative",
                    },
                    {
                        "control_type": "positive",
                        "status": "passed",
                        "control_id": "positive-behavior",
                        "predicate": planned["positive-behavior"],
                        "artifact_ref": "artifact-positive",
                    },
                ],
            },
        }
    )
    session = RunSession(
        project_path=str(tmp_path),
        trigger="skill_explicit",
        metadata={
            "remediation_packages": [{"package_id": bundle["package_id"]}],
            "skill_return": {"packages": [{"package_id": bundle["package_id"]}]},
            "vrtm": {"snapshot": baseline["snapshot"]},
        },
    )
    session.complete()
    session_dir = tmp_path / "sessions"
    SessionStore(str(session_dir)).save(session)
    bundle["metadata"]["session_id"] = session.session_id
    bundle["session_id"] = session.session_id
    return session, session_dir, bundle


def test_signed_remediation_approval_is_project_session_and_package_bound(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    state = tmp_path / "state"
    issued = issue_remediation_approval(
        str(project),
        session_id="run-1",
        package_id="REMEDIATION-1",
        reason="Approve bounded remediation of the agent tool policy",
        state_root=str(state),
    )

    approval = load_remediation_approval(
        issued["path"], str(project), session_id="run-1", package_id="REMEDIATION-1",
        state_root=str(state),
    )

    assert approval["trusted"] is True
    with pytest.raises(ValueError, match="different package"):
        load_remediation_approval(
            issued["path"], str(project), session_id="run-1", package_id="REMEDIATION-2",
            state_root=str(state),
        )


def test_retest_keeps_high_impact_package_open_without_operator_confirmation(tmp_path, monkeypatch):
    monkeypatch.setenv("VIBE_SEC_STATE_HOME", str(tmp_path / "state"))
    _success_regression(monkeypatch)
    session, session_dir, bundle = _prepared_session(tmp_path)

    result = asyncio.run(run_retest(
        str(tmp_path), [bundle], run_project_tests=False,
        session_dir=str(session_dir), session_id=session.session_id,
    ))

    closure = result["closure"]
    assert closure["closed_count"] == 0
    assert "signed local operator confirmation" in closure["packages"][0]["blockers"][0]
    persisted = SessionStore(str(session_dir)).load(session.session_id)
    assert persisted.metadata["retest"]["closure"]["open_count"] == 1
    assert any(event.event_type == "retest_completed" for event in persisted.events)


def test_retest_closes_only_after_signed_approval_regression_and_vrtm_binding(tmp_path, monkeypatch):
    state = tmp_path.parent / f"{tmp_path.name}-state"
    monkeypatch.setenv("VIBE_SEC_STATE_HOME", str(state))
    _success_regression(monkeypatch)
    session, session_dir, bundle = _prepared_session(tmp_path)
    approval = issue_remediation_approval(
        str(tmp_path),
        session_id=session.session_id,
        package_id=bundle["package_id"],
        reason="Approve the bounded authority-control remediation after code review",
        state_root=str(state),
    )

    result = asyncio.run(run_retest(
        str(tmp_path), [bundle], run_project_tests=False,
        session_dir=str(session_dir), session_id=session.session_id,
        approval_paths=[approval["path"]],
    ))

    assert result["closure"]["closed_count"] == 1
    assert result["closure"]["packages"][0]["status"] == "closed"
    assert result["updated_remediation_packages"][0]["state"] == "returned"
    statuses = {item["id"]: item["status"] for item in result["vrtm_model"]["threat_model"]["hypotheses"]}
    assert statuses[bundle["risk_hypothesis_ids"][0]] == "mitigated"
