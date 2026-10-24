import asyncio
import json

from agents.verification_agent import VerificationAgent
from core.runtime.docker_executor import DockerExecutor


def test_static_command_flow_can_be_confirmed_without_docker(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\n"
        "def run(user_input):\n"
        "    return os.system(user_input)\n",
        encoding="utf-8",
    )
    DockerExecutor._check_docker = lambda self: False
    agent = VerificationAgent()

    result = asyncio.run(agent.run({
        "project_path": str(tmp_path),
        "enable_react_verification": False,
        "findings_to_verify": [{
            "id": "cmd-1",
            "severity": "high",
            "vulnerability_type": "command_injection",
            "file_path": "app.py",
            "line_start": 3,
            "line_end": 3,
        }],
    }))

    finding = result.data["needs_evidence_findings"][0]
    assert finding["verification_status"] == "static_only"
    assert finding["verification_predicate"]
    assert finding["evidence_bundle"]["gaps"]


def test_static_secret_predicate_can_confirm_without_container(tmp_path):
    secret = "live-looking-secret-123"
    (tmp_path / "config.py").write_text(f"api_key = {secret!r}\n", encoding="utf-8")
    agent = VerificationAgent()

    result = asyncio.run(agent.run({
        "project_path": str(tmp_path),
        "enable_react_verification": False,
        "findings_to_verify": [{
            "id": "secret-1",
            "severity": "high",
            "vulnerability_type": "api_key",
            "file_path": "config.py",
            "line_start": 1,
            "line_end": 1,
        }],
    }))

    assert result.data["needs_evidence_findings"][0]["verification_status"] == "static_only"
    assert result.data["needs_evidence_findings"][0]["evidence_bundle"]["gaps"]
    assert secret not in json.dumps(result.data)


def test_verification_preserves_discovery_provenance_in_final_evidence_bundle(tmp_path):
    secret = "live-looking-secret-456"
    (tmp_path / "config.py").write_text(f"api_key = {secret!r}\n", encoding="utf-8")
    agent = VerificationAgent()

    result = asyncio.run(agent.run({
        "project_path": str(tmp_path),
        "enable_react_verification": False,
        "findings_to_verify": [{
            "id": "secret-with-scanner-evidence",
            "severity": "high",
            "vulnerability_type": "api_key",
            "file_path": "config.py",
            "line_start": 1,
            "line_end": 1,
            "artifact_refs": ["artifact-scanner-1"],
            "evidence_bundle": {
                "items": [{
                    "type": "scanner_signal",
                    "tool_execution_id": "execution-scanner-1",
                    "artifact_refs": ["artifact-scanner-1"],
                }],
                "gaps": ["Scanner signal has not been independently verified"],
                "level": 1,
                "artifact_refs": ["artifact-scanner-1"],
            },
        }],
    }))

    finding = result.data["needs_evidence_findings"][0]
    bundle = finding["evidence_bundle"]
    assert {item.get("type") for item in bundle["items"]} == {"scanner_signal", None}
    assert bundle["items"][1]["evidence_type"] == "static"
    assert bundle["artifact_refs"] == ["artifact-scanner-1"]
    assert bundle["tool_execution_ids"] == ["execution-scanner-1"]
    assert bundle["gaps"]
    assert bundle["discovery_gaps"] == ["Scanner signal has not been independently verified"]
    assert secret not in json.dumps(bundle)


def test_github_actions_protocol_validator_confirms_direct_event_interpolation(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "triage.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "name: triage\n"
        "on: issues\n"
        "jobs:\n"
        "  issue:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ${{ github.event.issue.title }}\n",
        encoding="utf-8",
    )

    result = asyncio.run(VerificationAgent().run({
        "project_path": str(tmp_path),
        "enable_react_verification": False,
        "findings_to_verify": [{
            "id": "workflow-1",
            "severity": "high",
            "vulnerability_type": "workflow_insecurity",
            "file_path": ".github/workflows/triage.yml",
            "line_start": 7,
            "line_end": 7,
        }],
    }))

    finding = result.data["needs_evidence_findings"][0]
    assert finding["verification_status"] == "static_only"
    assert finding["verification_evidence"]["data"]["protocol_analyzer"] == "github_actions_yaml"
    assert finding["verification_evidence"]["data"]["can_confirm_statically"] is True


def test_mcp_ast_validator_keeps_missing_global_policy_as_needs_evidence(tmp_path):
    (tmp_path / "server.py").write_text(
        "import subprocess\n"
        "@mcp.tool()\n"
        "def run_admin(command):\n"
        "    return subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    result = asyncio.run(VerificationAgent().run({
        "project_path": str(tmp_path),
        "enable_react_verification": False,
        "findings_to_verify": [{
            "id": "mcp-1",
            "severity": "high",
            "vulnerability_type": "mcp_insecurity",
            "file_path": "server.py",
            "line_start": 3,
            "line_end": 4,
        }],
    }))

    finding = result.data["needs_evidence_findings"][0]
    assert finding["verification_evidence"]["data"]["protocol_analyzer"] == "mcp_python_ast"
    assert finding["verification_evidence"]["data"]["can_confirm_statically"] is False
    assert finding["evidence_bundle"]["gaps"]


def test_protocol_validator_rejects_fixed_github_actions_interpolation(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "triage.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "name: triage\n"
        "jobs:\n"
        "  issue:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          ISSUE_TITLE: ${{ github.event.issue.title }}\n"
        "        run: printf '%s\\n' \"$ISSUE_TITLE\"\n",
        encoding="utf-8",
    )

    result = asyncio.run(VerificationAgent().run({
        "project_path": str(tmp_path),
        "enable_react_verification": False,
        "findings_to_verify": [{
            "id": "workflow-fixed",
            "severity": "high",
            "vulnerability_type": "workflow_insecurity",
            "file_path": ".github/workflows/triage.yml",
            "line_start": 8,
            "line_end": 8,
        }],
    }))

    finding = result.data["rejected_findings"][0]
    assert finding["verification_status"] == "rejected"
    assert finding["verification_evidence"]["outcome"] == "contradicted"


def test_mcp_config_wildcard_is_independently_confirmable(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({
            "mcpServers": {
                "ops": {"tools": [{"name": "shell", "permissions": ["*"]}]},
            },
        }),
        encoding="utf-8",
    )

    result = asyncio.run(VerificationAgent().run({
        "project_path": str(tmp_path),
        "enable_react_verification": False,
        "findings_to_verify": [{
            "id": "mcp-config-1",
            "severity": "high",
            "vulnerability_type": "mcp_insecurity",
            "file_path": "mcp.json",
            "line_start": 1,
            "line_end": 1,
        }],
    }))

    finding = result.data["needs_evidence_findings"][0]
    assert finding["verification_status"] == "static_only"
    assert finding["verification_evidence"]["data"]["protocol_analyzer"] == "mcp_config"
    assert finding["verification_evidence"]["data"]["can_confirm_statically"] is True


def test_docker_executor_refuses_unpredicated_verification():
    executor = DockerExecutor()
    result = asyncio.run(executor.verify_vulnerability("command_injection", "print('runs')"))

    assert result["verified"] is False
    assert result["status"] == "needs_evidence"
    assert "not executed" in result["evidence"]
