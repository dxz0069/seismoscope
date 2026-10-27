import asyncio
import json
import subprocess
import sys

from agents.verification_agent import VerificationAgent
from core.runtime.docker_executor import DockerExecutor
from core.verification.poc_protocol import bind_poc_verdict, validate_poc_plan


def _finding():
    return {
        "id": "cmd-1",
        "vulnerability_type": "command_injection",
        "severity": "high",
        "file_path": "app.py",
        "line_start": 1,
        "line_end": 1,
    }


def _plan():
    return {
        "finding_id": "cmd-1",
        "vulnerability_type": "command_injection",
        "goal": "Prove attacker-controlled input reaches a shell",
        "harness_kind": "python",
        "predicate": "Positive emits VIBE_SEC_VERIFIED and negative does not",
        "success_marker": "VIBE_SEC_VERIFIED",
        "exploit_harness": "print('VIBE_SEC_VERIFIED=true')",
        "negative_control_harness": "print('VIBE_SEC_VERIFIED=false')",
    }


def test_poc_plan_requires_trusted_harness_authorization(tmp_path):
    (tmp_path / "app.py").write_text("import os; os.system(user_input)\n", encoding="utf-8")
    blocked = validate_poc_plan(
        _plan(), finding=_finding(), trusted_authorization={}, project_root=str(tmp_path),
    )
    allowed = validate_poc_plan(
        _plan(),
        finding=_finding(),
        trusted_authorization={
            "_trusted_authorization_verified": True,
            "allow_poc_execution": True,
            "non_production": True,
        },
        project_root=str(tmp_path),
    )

    assert blocked.executable is False
    assert "allow_poc_execution=true" in blocked.gaps[0]
    assert allowed.executable is True
    assert allowed.plan.fingerprint() == allowed.plan.to_dict()["fingerprint"]
    assert allowed.plan.to_dict()["target_binding"]["path"] == "app.py"
    assert "target_code" not in allowed.plan.to_dict()


def test_negative_control_match_invalidates_experiment_instead_of_rejecting_finding(tmp_path):
    (tmp_path / "app.py").write_text("import os; os.system(user_input)\n", encoding="utf-8")
    validation = validate_poc_plan(
        _plan(),
        finding=_finding(),
        trusted_authorization={
            "_trusted_authorization_verified": True,
            "allow_poc_execution": True,
        },
        project_root=str(tmp_path),
    )
    result = bind_poc_verdict(
        validation,
        positive_matched=True,
        negative_matched=True,
    )

    assert result["verdict"] == "needs_evidence"


def test_verification_agent_persists_non_executable_poc_contract(tmp_path):
    (tmp_path / "app.py").write_text("import os; os.system(user_input)\n", encoding="utf-8")
    finding = {**_finding(), "poc_plan": _plan()}

    result = asyncio.run(VerificationAgent().run({
        "project_path": str(tmp_path),
        "enable_react_verification": False,
        "findings_to_verify": [finding],
        "verification_authorization": {},
    }))

    checked = result.data["needs_evidence_findings"][0]
    assert checked["poc"]["contract"] == "vibe-sec.poc-plan.v2"
    assert checked["poc"]["executable"] is False
    dynamic = checked["verification_evidence"]["data"]["items"][1]
    assert dynamic["data"]["poc_validation"]["gaps"]


def test_poc_plan_is_invalidated_when_bound_source_changes(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("import os; os.system(user_input)\n", encoding="utf-8")
    authorization = {
        "_trusted_authorization_verified": True,
        "allow_poc_execution": True,
    }
    initial = validate_poc_plan(
        _plan(), finding=_finding(), trusted_authorization=authorization,
        project_root=str(tmp_path),
    )
    stored_plan = initial.plan.to_dict()

    source.write_text("def safe(user_input):\n    return user_input\n", encoding="utf-8")
    stale = validate_poc_plan(
        stored_plan, finding=_finding(), trusted_authorization=authorization,
        project_root=str(tmp_path),
    )

    assert stale.executable is False
    assert "source hash is stale" in stale.gaps[0]
    assert stale.plan.target_binding.sha256 != stored_plan["target_binding"]["sha256"]


def test_harness_owned_command_oracle_ignores_self_asserted_success_marker():
    target = "import os\ndef run(value):\n    return os.system(value)\n"
    forged = DockerExecutor._build_verification_script(
        "command_injection", target, "VIBE_SEC_VERIFIED = True",
        target_path="app.py",
    )
    positive = DockerExecutor._build_verification_script(
        "command_injection", target, "run('controlled-value')",
        target_path="app.py",
    )

    forged_run = subprocess.run(
        [sys.executable, "-I", "-c", forged], capture_output=True, text=True, check=False,
    )
    positive_run = subprocess.run(
        [sys.executable, "-I", "-c", positive], capture_output=True, text=True, check=False,
    )
    forged_result = json.loads(forged_run.stdout.splitlines()[-1])
    positive_result = json.loads(positive_run.stdout.splitlines()[-1])

    assert forged_result["verified"] is False
    assert forged_result["events"] == []
    assert positive_result["verified"] is True
    assert positive_result["events"][0]["sink"] == "os.system"
