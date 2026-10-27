import asyncio
import json

import core.surface.runtime_surface as runtime_surface_module
import core.tool_fabric.framework_semantics as framework_semantics_module
from agents.audit_agent import AuditAgent, AuditState
from agents.verification_agent import VerificationAgent
from core.agent_runtime.completion import FinalizeFindingContract
from core.agents.registry import AgentRegistry
from core.audit.react_review import ReActFindingReviewer
from core.llm_service import MockLLMService
from core.orchestrator.orchestrator import OrchestrationConfig, OrchestratorAgent
from core.policy.trigger_policy import TriggerPolicy
from core.surface.risk_chain import RiskChainBuilder
from core.surface.runtime_surface import RuntimeSurface, RuntimeSurfaceBuilder


def test_finalize_finding_contract_allows_harness_bound_tool_evidence():
    result = FinalizeFindingContract().validate({
        "id": "finding-1",
        "title": "Bound finding",
        "severity": "high",
        "vulnerability_type": "xss",
        "description": "Unsafe HTML assignment",
        "file_path": "app.js",
        "line_start": 1,
        "line_end": 1,
        "verdict": "potential",
    })

    assert result.valid is True


def test_interrupted_review_keeps_source_grounded_confirmed_verdict():
    candidate = {
        "id": "finding-1",
        "title": "Hardcoded key",
        "severity": "high",
        "vulnerability_type": "api_key",
        "description": "Key remains in source",
        "file_path": "config.py",
        "line_start": 1,
        "line_end": 1,
        "confidence": 0.82,
        "evidence": [],
    }
    status, output = ReActFindingReviewer._bind_review_result(
        candidate,
        None,
        "failed",
        {"verdict": "confirmed", "confidence": 0.82},
        [{
            "tool_name": "read_source",
            "allowed": True,
            "status": "completed",
            "output": {"file_path": "config.py", "content": "api_key = '<redacted>'"},
        }],
        "maximum turn limit reached",
    )

    assert status == "degraded"
    assert output["verdict"] == "confirmed"
    assert output["confidence"] == 0.82
    assert output["review_metadata"]["degradation_reason"] == "interrupted"
    assert output["review_metadata"]["operational_gaps"]
    assert output["review_metadata"]["evidence_gaps"] == []
    assert "maximum turn limit reached" not in json.dumps(output)
    assert "turn_limit_reached" in json.dumps(output)


def test_verification_normalizes_llm_secret_type(tmp_path):
    (tmp_path / "config.py").write_text(
        "client_secret = 'live-looking-secret-123'\n",
        encoding="utf-8",
    )
    finding = {
        "id": "secret-1",
        "severity": "high",
        "vulnerability_type": "hardcoded_secrets",
        "file_path": "config.py",
        "line_start": 1,
        "line_end": 1,
    }

    evidence = asyncio.run(VerificationAgent()._static_verification(str(tmp_path), finding))

    assert evidence.success is True
    assert evidence.data["can_confirm_statically"] is True
    assert evidence.data["canonical_vulnerability_type"] == "secret_leak"


def test_runtime_surface_falls_back_when_parser_pack_is_unavailable(tmp_path, monkeypatch):
    (tmp_path / "app.ts").write_text(
        "const systemPrompt = 'Summarize input';\n"
        "preview.innerHTML = request.body;\n",
        encoding="utf-8",
    )

    def unavailable(_language):
        raise RuntimeError("parser download unavailable")

    monkeypatch.setattr(runtime_surface_module, "get_parser", unavailable)
    monkeypatch.setattr(framework_semantics_module, "get_parser", unavailable)
    surface = asyncio.run(RuntimeSurfaceBuilder(str(tmp_path)).build())

    coverage = surface.metadata["extraction_coverage"]
    assert coverage["extractors"]["tree_sitter"] is False
    assert coverage["extractors"]["javascript_fallback"] is True
    assert any(item.name == "systemPrompt" for item in surface.prompt_configs)
    assert any(item.sink_type == "innerHTML" for item in surface.browser_sinks)
    assert coverage["parse_failures"][0]["fallback"] == "local_line_analysis"


def test_trigger_policy_uses_added_code_and_ignores_comment_only_diff():
    policy = TriggerPolicy()
    decision = policy.evaluate(
        ["src/config.py", "src/auth.py", "README.md"],
        diffs={
            "src/config.py": "+password = 'hardcoded-value'\n",
            "src/auth.py": "+# Explain the existing authentication check\n",
            "README.md": "+password = 'documentation-only'\n",
        },
    )

    assert decision.mode == "suggest"
    assert decision.matched_paths == ["src/config.py"]
    assert "security_sensitive_diff" in decision.reasons


def test_trigger_policy_supports_project_override(tmp_path):
    config_dir = tmp_path / ".vibe-sec"
    config_dir.mkdir()
    (config_dir / "trigger-policy.yaml").write_text(
        "threshold: 6\npath_weights:\n  auth: 2\n",
        encoding="utf-8",
    )

    decision = TriggerPolicy(str(tmp_path)).evaluate(["src/auth.py"])

    assert decision.mode == "none"


def test_risk_chain_reports_missing_boundary_without_inventing_bypass():
    surface = RuntimeSurface(project_path=".")
    chain = RiskChainBuilder(surface).build_risk_chains([{
        "id": "finding-1",
        "vulnerability_type": "sql_injection",
        "severity": "high",
        "file_path": "app.py",
        "line_start": 3,
        "evidence": [{"type": "code_snippet"}],
    }])[0]

    assert chain.boundary_path == []
    assert chain.boundary_gap is True
    assert chain.to_dict()["boundary_gap"] is True
    assert chain.overall_confidence < 0.6


def test_agent_audit_ignores_test_files_and_approval_guarded_admin_permissions(tmp_path):
    test_file = tmp_path / "tests" / "test_agent.py"
    test_file.parent.mkdir()
    test_file.write_text(
        "permissions = 'admin'\n"
        "def delete_record():\n"
        "    pass\n",
        encoding="utf-8",
    )
    (tmp_path / "guarded_agent.py").write_text(
        "permissions = 'admin'\n"
        "requires_approval = True\n"
        "def delete_record():\n"
        "    pass\n",
        encoding="utf-8",
    )

    agent = AuditAgent()
    agent.audit_state = AuditState()
    asyncio.run(agent._scan_agent_vulnerabilities(str(tmp_path), {"excessive_agency"}))

    assert agent.audit_state.candidates == []


def test_agent_audit_keeps_unapproved_privileged_destructive_agent(tmp_path):
    (tmp_path / "autonomous_agent.py").write_text(
        "permissions = 'admin'\n"
        "requires_approval = False\n"
        "def delete_record():\n"
        "    return remove_all_records()\n",
        encoding="utf-8",
    )
    agent = AuditAgent()
    agent.audit_state = AuditState()

    asyncio.run(agent._scan_agent_vulnerabilities(str(tmp_path), {"excessive_agency"}))

    assert [item.vulnerability_type for item in agent.audit_state.candidates] == ["excessive_agency"]


def test_verification_budget_scales_and_defers_findings_with_reason():
    orchestrator = OrchestratorAgent(
        MockLLMService(),
        AgentRegistry(),
        OrchestrationConfig(max_verification_count=2, verification_fraction=0.30),
    )
    orchestrator.state.merged_findings = [
        {
            "id": f"finding-{index}",
            "vulnerability_type": f"type-{index % 4}",
            "severity": "high" if index < 8 else "medium",
            "confidence": 0.8,
        }
        for index in range(20)
    ]
    orchestrator.state.merged_findings.append({
        "id": "below-threshold", "vulnerability_type": "low-confidence",
        "severity": "low", "confidence": 0.2,
    })

    selected = orchestrator._filter_findings_for_verification()
    deferred_reasons = {item["id"]: item["verification_reason"] for item in orchestrator.state.not_reviewed_findings}

    assert len(selected) == 6
    assert deferred_reasons["below-threshold"] == "below_verification_threshold"
    assert all(reason == "verification_budget_exceeded" for finding_id, reason in deferred_reasons.items() if finding_id != "below-threshold")
