"""Tests for hardened container commands and scanner normalization."""

import asyncio
import json
from pathlib import Path

from agents.audit_agent import AuditAgent, AuditState, CandidateCase
from core.agents.base import Severity
from core.runtime.permission_policy import PermissionPolicy
from core.tool_fabric import (
    ArtifactStore,
    ContainerImagePreflight,
    ContainerProfile,
    ContainerRunResult,
    ContainerToolRunner,
    ToolGateway,
    ToolExecutionStatus,
    ToolRegistry,
    ToolRequest,
    ImagePreflightResult,
    register_container_scanners,
    register_active_scanners,
)


def test_container_command_has_read_only_and_resource_boundaries(tmp_path):
    command = ContainerToolRunner().build_command(
        ["semgrep", "scan", "--json", "/workspace"],
        project_root=str(tmp_path),
        profile=ContainerProfile(image="vibe-sec-tools:test"),
    )

    joined = " ".join(command)
    assert "--network none" in joined
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges:true" in command
    assert "--read-only" in command
    assert "--pids-limit 256" in joined
    mount = command[command.index("--mount") + 1]
    assert "target=/workspace,ro" in mount
    assert command[-1] == "/workspace"


class FakeRunner:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.commands = []

    async def run(self, command, *, project_root, profile, timeout_seconds, env=None):
        self.commands.append({
            "command": command,
            "project_root": project_root,
            "profile": profile,
            "timeout_seconds": timeout_seconds,
            "env": env,
        })
        return self.outputs.pop(0)


def test_semgrep_and_gitleaks_adapters_normalize_signals_without_secret_values(tmp_path):
    semgrep_output = json.dumps({
        "results": [{
            "check_id": "python.sql-injection",
            "path": "/workspace/app.py",
            "start": {"line": 4},
            "end": {"line": 4},
            "extra": {"message": "Dynamic SQL", "severity": "ERROR", "metadata": {}},
        }],
        "errors": [],
    })
    gitleaks_output = json.dumps([{
        "RuleID": "generic-api-key",
        "Description": "Generic API key",
        "File": "/workspace/config.py",
        "StartLine": 2,
        "EndLine": 2,
        "Match": 'API_KEY = "do-not-return-this"',
        "Secret": "do-not-return-this",
        "Fingerprint": "config.py:generic-api-key:2",
    }])
    runner = FakeRunner([
        ContainerRunResult("completed", [], 0, semgrep_output),
        ContainerRunResult("completed", [], 0, gitleaks_output),
    ])
    registry = ToolRegistry()
    register_container_scanners(
        registry,
        runner=runner,
        profile=ContainerProfile(image="vibe-sec-tools:test"),
    )
    gateway = ToolGateway(
        registry,
        project_root=str(tmp_path),
        artifact_store=ArtifactStore(str(tmp_path / "artifacts"), session_id="scanner-test"),
    )

    semgrep = asyncio.run(gateway.execute(ToolRequest(
        tool_name="semgrep_scan",
        arguments={"path": ".", "rule_pack": "web"},
    )))
    gitleaks = asyncio.run(gateway.execute(ToolRequest(
        tool_name="gitleaks_scan",
        arguments={"path": "."},
    )))

    assert semgrep.signals[0].rule_id == "python.sql-injection"
    assert semgrep.signals[0].file_path == "app.py"
    assert semgrep.signals[0].severity == "high"
    assert gitleaks.signals[0].file_path == "config.py"
    assert gitleaks.output["secret_values_exposed"] is False
    assert "do-not-return-this" not in json.dumps(gitleaks.output)
    artifact_text = Path(gitleaks.artifacts[0].path).read_text(encoding="utf-8")
    assert "do-not-return-this" not in artifact_text
    artifact_payload = json.loads(artifact_text)
    assert artifact_payload[0]["Secret"] == "[REDACTED]"
    assert artifact_payload[0]["Match"].startswith('API_KEY = "[REDACTED sha256:')
    assert artifact_payload[0]["Match"].endswith('len:18]"')
    assert runner.commands[0]["command"][0] == "semgrep"
    assert runner.commands[0]["env"] == {"HOME": "/tmp"}
    assert runner.commands[1]["command"][0] == "gitleaks"


def test_scanner_failure_retains_raw_artifact_and_diagnostics(tmp_path):
    runner = FakeRunner([
        ContainerRunResult(
            "failed",
            ["docker", "run", "semgrep"],
            125,
            stderr="docker daemon unavailable",
            error="Container tool exited with code 125",
        ),
    ])
    registry = ToolRegistry()
    register_container_scanners(
        registry,
        runner=runner,
        profile=ContainerProfile(image="vibe-sec-tools:test"),
    )
    artifact_store = ArtifactStore(str(tmp_path / "artifacts"), session_id="scanner-failure")
    gateway = ToolGateway(
        registry,
        project_root=str(tmp_path),
        artifact_store=artifact_store,
    )

    execution = asyncio.run(gateway.execute(ToolRequest(
        tool_name="semgrep_scan",
        arguments={"path": "."},
    )))

    assert execution.status == ToolExecutionStatus.FAILED
    assert execution.error == "Container tool exited with code 125"
    assert execution.output["scanner_status"] == "failed"
    assert execution.output["exit_code"] == 125
    assert len(execution.artifacts) == 1
    assert execution.artifacts[0].sha256
    assert Path(execution.artifacts[0].path).read_text(encoding="utf-8") == "docker daemon unavailable"


def test_scanner_invalid_json_retains_raw_artifact(tmp_path):
    runner = FakeRunner([
        ContainerRunResult("completed", ["docker", "run", "semgrep"], 0, "not-json"),
    ])
    registry = ToolRegistry()
    register_container_scanners(registry, runner=runner, profile=ContainerProfile())
    artifact_store = ArtifactStore(str(tmp_path / "artifacts"), session_id="scanner-json")
    gateway = ToolGateway(
        registry,
        project_root=str(tmp_path),
        artifact_store=artifact_store,
    )

    execution = asyncio.run(gateway.execute(ToolRequest(tool_name="semgrep_scan")))

    assert execution.status == ToolExecutionStatus.FAILED
    assert "invalid JSON" in execution.error
    assert execution.artifacts
    assert Path(execution.artifacts[0].path).read_bytes() == b"not-json"


def test_bandit_trivy_and_codeql_normalize_without_exposing_trivy_secret(tmp_path):
    bandit = json.dumps({
        "results": [{
            "filename": "/workspace/app.py", "line_number": 7, "line_range": [7],
            "issue_text": "subprocess call with shell=True", "issue_severity": "HIGH",
            "issue_confidence": "HIGH", "test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true",
        }],
        "metrics": {},
    })
    trivy = json.dumps({
        "Results": [{
            "Target": "/workspace/config.py",
            "Secrets": [{
                "RuleID": "generic-api-key", "Title": "API key", "Severity": "HIGH",
                "StartLine": 2, "EndLine": 2, "Match": "live-secret-value", "Secret": "live-secret-value",
            }],
            "Misconfigurations": [{
                "ID": "CFG-1", "Title": "Unsafe config", "Severity": "MEDIUM",
                "CauseMetadata": {"StartLine": 4, "EndLine": 5},
            }],
        }],
    })
    trivy_version = json.dumps({
        "Version": "0.58.2",
        "VulnerabilityDB": {
            "Version": 2,
            "UpdatedAt": "2026-07-22T01:05:55Z",
            "DownloadedAt": "2026-07-22T07:00:49Z",
        },
    })
    codeql = json.dumps({
        "runs": [{"results": [{
            "ruleId": "py/sql-injection", "level": "error",
            "message": {"text": "SQL query built from user input"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "/workspace/app.py"},
                "region": {"startLine": 12, "endLine": 13},
            }}],
        }]}],
    })
    runner = FakeRunner([
        ContainerRunResult("completed", [], 0, bandit),
        ContainerRunResult("completed", [], 0, trivy_version),
        ContainerRunResult("completed", [], 0, trivy),
        ContainerRunResult("completed", [], 0, codeql),
    ])
    registry = ToolRegistry()
    register_container_scanners(registry, runner=runner, profile=ContainerProfile())
    gateway = ToolGateway(
        registry,
        project_root=str(tmp_path),
        artifact_store=ArtifactStore(str(tmp_path / "artifacts"), session_id="expanded-scanners"),
    )
    (tmp_path / ".codeql" / "db").mkdir(parents=True)

    bandit_run = asyncio.run(gateway.execute(ToolRequest("bandit_scan", {"path": "."})))
    trivy_run = asyncio.run(gateway.execute(ToolRequest(
        "trivy_filesystem_scan", {"path": ".", "scanners": "secret"},
    )))
    codeql_run = asyncio.run(gateway.execute(ToolRequest(
        "codeql_database_scan", {"database_path": ".codeql/db", "language": "python"},
    )))

    assert bandit_run.signals[0].rule_id == "B602"
    assert bandit_run.signals[0].severity == "high"
    assert trivy_run.signals[0].kind == "configuration_finding"
    assert {item.kind for item in trivy_run.signals} == {"configuration_finding", "secret_finding"}
    assert "live-secret-value" not in Path(trivy_run.artifacts[0].path).read_text(encoding="utf-8")
    assert trivy_run.output["database"]["Version"] == 2
    assert trivy_run.artifacts[0].metadata["database"]["DownloadedAt"]
    assert codeql_run.signals[0].kind == "dataflow_finding"
    assert codeql_run.signals[0].file_path == "app.py"
    assert runner.commands[1]["profile"].image == "vibe-sec-trivy:latest"
    assert runner.commands[1]["env"]["TRIVY_CACHE_DIR"] == "/opt/trivy-cache"
    assert runner.commands[3]["profile"].image == "vibe-sec-codeql:latest"
    assert runner.commands[3]["command"][4] == "/opt/vibe-sec/codeql-suites/python-security-extended.qls"


def test_image_preflight_only_registers_accepted_capabilities():
    class FakePreflight(ContainerImagePreflight):
        def inspect(self, requirement):
            accepted = requirement.image != "vibe-sec-codeql:latest"
            return ImagePreflightResult(
                requirement.image,
                accepted,
                set(requirement.capabilities) if accepted else set(),
                requirement.version if accepted else "",
                reason="accepted" if accepted else "missing",
            )

    registry = ToolRegistry()
    report = register_container_scanners(
        registry,
        runner=FakeRunner([]),
        preflight=FakePreflight(),
        verify_images=True,
    )

    names = {item.name for item in registry.specs()}
    assert {"semgrep_scan", "gitleaks_scan", "bandit_scan", "trivy_filesystem_scan"} <= names
    assert "codeql_database_scan" not in names
    assert report["codeql"]["available"] is False


def test_nuclei_requires_registration_and_network_target_policy(tmp_path):
    output = json.dumps({
        "template-id": "exposed-panel", "matched-at": "http://127.0.0.1:8000/admin",
        "info": {"name": "Exposed admin panel", "severity": "high"},
    })
    runner = FakeRunner([ContainerRunResult("completed", [], 0, output + "\n")])
    registry = ToolRegistry()
    register_active_scanners(
        registry,
        runner=runner,
        profile=ContainerProfile(image="vibe-sec-nuclei:test", network="bridge"),
    )
    store = ArtifactStore(str(tmp_path / "artifacts"), session_id="nuclei")
    blocked_gateway = ToolGateway(
        registry, project_root=str(tmp_path), artifact_store=store,
        policy=PermissionPolicy(allow_network_access=False, allow_file_write=False),
    )
    request = ToolRequest(
        "nuclei_service_scan",
        {"target_url": "http://127.0.0.1:8000", "template_profile": "safe-http"},
    )

    blocked = asyncio.run(blocked_gateway.execute(request))
    assert blocked.status == ToolExecutionStatus.BLOCKED
    assert runner.commands == []

    allowed_gateway = ToolGateway(
        registry, project_root=str(tmp_path), artifact_store=store,
        policy=PermissionPolicy(
            allowed_domains=["127.0.0.1"], allow_network_access=True, allow_file_write=False,
        ),
    )
    allowed = asyncio.run(allowed_gateway.execute(request))
    assert allowed.status == ToolExecutionStatus.COMPLETED
    assert allowed.signals[0].rule_id == "exposed-panel"
    assert runner.commands[0]["profile"].network == "bridge"


def test_scanner_signal_merges_with_existing_candidate_and_preserves_artifact():
    agent = AuditAgent()
    agent.audit_state = AuditState(candidates=[CandidateCase(
        id="deterministic-1",
        vulnerability_type="sql_injection",
        severity=Severity.MEDIUM,
        file_path="src/app.py",
        line_start=10,
        line_end=10,
        description="Dynamic SQL candidate",
        evidence=[{"type": "code_snippet", "content": "execute(query)"}],
        confidence=0.6,
    )])

    agent._ingest_scanner_signals([{
        "kind": "static_finding",
        "rule_id": "python.sql-injection",
        "file_path": "src\\app.py",
        "line_start": 12,
        "line_end": 12,
        "severity": "high",
        "confidence": 0.85,
        "tool_execution_id": "execution-1",
        "artifact_refs": ["artifact-1"],
    }])
    findings = asyncio.run(agent._generate_findings())

    assert len(agent.audit_state.candidates) == 1
    assert agent.audit_state.candidates[0].severity == Severity.HIGH
    assert agent.audit_state.candidates[0].confidence == 0.85
    assert findings[0]["evidence_bundle"]["artifact_refs"] == ["artifact-1"]
    scanner_evidence = next(
        item for item in findings[0]["evidence_bundle"]["items"]
        if item.get("type") == "scanner_signal"
    )
    assert scanner_evidence["tool_execution_id"] == "execution-1"
