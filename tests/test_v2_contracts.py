"""Focused tests for the V2 harness contracts."""

import asyncio
import json

from agents.verification_agent import VerificationEvidence
from core.agent_runtime.completion import FinalizeFindingContract, FinalizeVerificationContract
from core.audit.lanes import AuditLane, classify_lane
from core.audit.models import normalize_finding
from core.audit.react_review import ReActFindingReviewer
from core.harness.models import RuntimeSurfaceGraph
from core.harness.return_protocol import build_return_packages
from core.llm_service import LLMResponse, MockLLMService
from core.policy.trigger_policy import TriggerPolicy
from core.session.models import RunSession, RunStatus
from core.surface.runtime_surface import RuntimeSurfaceBuilder
from core.surface.threat_model import RuntimeThreatModelAnalyzer
from core.verification.react_review import ReActVerificationReviewer


def test_finding_contract_assigns_stable_id_and_lane():
    finding = normalize_finding(
        {
            "title": "Unsafe prompt construction",
            "severity": "high",
            "vulnerability_type": "prompt_injection",
        },
        index=7,
    )

    assert finding["id"] == "FINDING-007"
    assert classify_lane(finding) == AuditLane.AGENT.value
    assert finding["evidence_bundle"]["level"] == 1


def test_finding_normalization_preserves_existing_evidence_bundle():
    finding = normalize_finding({
        "id": "finding-1",
        "title": "Evidence-bearing finding",
        "severity": "high",
        "vulnerability_type": "prompt_injection",
        "evidence_bundle": {
            "items": [{"type": "surface", "summary": "path matched"}],
            "gaps": ["runtime validation pending"],
            "level": 2,
            "artifact_refs": ["artifact://one"],
        },
    })

    assert finding["evidence_bundle"]["items"][0]["type"] == "surface"
    assert finding["evidence_bundle"]["gaps"] == ["runtime validation pending"]
    assert finding["evidence_bundle"]["level"] == 2
    assert finding["artifact_refs"] == ["artifact://one"]


def test_return_protocol_preserves_evidence_and_retest_gate():
    packages = build_return_packages(
        [{
            "id": "FINDING-001",
            "title": "Unsafe tool",
            "severity": "high",
            "vulnerability_type": "excessive_agency",
            "verification_status": "verified",
            "evidence_bundle": {"items": [{"type": "code_snippet"}], "gaps": [], "level": 2},
        }],
        [{"package_id": "REMEDIATION-FINDING-001", "finding_id": "FINDING-001", "ai_patch_prompt": "Require approval."}],
    )

    assert packages[0]["remediation"]["ai_patch_prompt"] == "Require approval."
    assert packages[0]["return_contract"]["requires_human_confirmation"] is True
    assert packages[0]["return_contract"]["retest_required"] is True


def test_trigger_policy_is_conservative_for_automatic_changes():
    decision = TriggerPolicy().evaluate(["src/auth/service.py", "README.md"])

    assert decision.should_audit is False
    assert decision.mode == "suggest"
    assert decision.matched_paths == ["src/auth/service.py"]


def test_session_records_checkpoint_and_completion():
    session = RunSession(project_path=".")
    session.start()
    session.emit("phase_started", "plan", "started")
    checkpoint = session.checkpoint("plan", {"scope": "full"})
    session.complete()

    assert checkpoint.phase == "plan"
    assert session.status == RunStatus.COMPLETED
    assert session.to_dict()["events"][0]["event_type"] == "phase_started"


def test_surface_graph_ids_are_stable_for_same_surface():
    class EmptySurface:
        page_entries = []
        prompt_configs = []
        tool_profiles = []
        permission_profiles = []
        trust_boundaries = []
        code_blocks = []

    first = RuntimeSurfaceGraph.from_surface(EmptySurface()).to_dict()
    second = RuntimeSurfaceGraph.from_surface(EmptySurface()).to_dict()

    assert first == second


def test_runtime_threat_model_emits_path_and_evidence_predicates(tmp_path):
    async def build():
        source = tmp_path / "app.py"
        source.write_text(
            "system_prompt = 'Answer user input'\n"
            "def shell_tool(query):\n"
            "    return os.system(query)\n",
            encoding="utf-8",
        )
        surface = await RuntimeSurfaceBuilder(str(tmp_path)).build()
        graph = RuntimeSurfaceGraph.from_surface(surface)
        return RuntimeThreatModelAnalyzer(surface, graph).analyze()

    model = asyncio.run(build())

    assert model.version == "0.4"
    assert model.hypotheses
    assert all(item.attack_path for item in model.hypotheses)
    assert all(item.evidence_predicates for item in model.hypotheses)
    assert model.coverage["hypothesis_count"] == len(model.hypotheses)


def test_runtime_graph_visualization_is_frontend_ready(tmp_path):
    source = tmp_path / "agent_app.py"
    source.write_text(
        "system_prompt = 'Answer user input'\n"
        "def shell_tool(query):\n"
        "    return os.system(query)\n",
        encoding="utf-8",
    )

    async def build_projection():
        surface = await RuntimeSurfaceBuilder(str(tmp_path)).build()
        graph = RuntimeSurfaceGraph.from_surface(surface)
        threat_model = RuntimeThreatModelAnalyzer(surface, graph).analyze()
        return graph.to_visualization(threat_model.to_dict())

    projection = asyncio.run(build_projection())

    assert projection["schema"] == "vibe-sec.runtime-surface-visualization"
    assert projection["version"] == "1"
    assert projection["layout"]["direction"] == "LR"
    assert projection["nodes"]
    assert projection["edges"]
    assert projection["risk_paths"]
    assert projection["legend"]["red_path"]
    assert any(node["style"].get("risk") for node in projection["nodes"])
    assert all("security" in node and "risk_hypothesis_ids" in node for node in projection["nodes"])
    assert all("risk_hypothesis_ids" in edge for edge in projection["edges"])
    assert projection["default_view"] == "risk_overview"

    overview = projection["projections"]["risk_overview"]
    assert 1 <= len(overview["nodes"]) <= 7
    assert all(node["type"] != "code_block" for node in overview["nodes"])
    assert all(node["attributes"]["represented_node_count"] >= 1 for node in overview["nodes"])
    assert overview["collapsed_implementation_node_count"] >= 1
    assert overview["source_node_count"] == len(projection["nodes"])
    assert {
        node_id
        for path in overview["risk_paths"]
        for node_id in path["path_node_ids"]
    }.issubset({node["id"] for node in overview["nodes"]})


def test_finalize_finding_contract_distinguishes_open_evidence_gaps():
    base = {
        "id": "finding-1",
        "title": "Potential issue",
        "severity": "high",
        "vulnerability_type": "prompt_injection",
        "description": "Evidence supports a potential issue.",
        "file_path": "app.py",
        "line_start": 1,
        "line_end": 1,
        "evidence_bundle": {"items": [{"type": "code_snippet"}], "gaps": ["dynamic validation unavailable"]},
    }

    contract = FinalizeFindingContract()
    potential = contract.validate({**base, "verdict": "potential"})
    confirmed = contract.validate({**base, "verdict": "confirmed"})

    assert potential.valid is True
    assert confirmed.valid is False


def test_react_finding_reviewer_collects_tool_evidence_and_finalizes(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("value = request.args['q']\n", encoding="utf-8")
    checkpoints = []

    class RecordingMockLLMService(MockLLMService):
        def __init__(self, responses):
            super().__init__(responses=responses)
            self.messages_seen = []

        async def chat(self, messages, **kwargs):
            self.messages_seen.append([message.to_dict() for message in messages])
            return await super().chat(messages, **kwargs)

    llm = RecordingMockLLMService(
        responses=[
            LLMResponse(
                content="I need source evidence.",
                tool_calls=[{
                    "id": "read-1",
                    "function": {
                        "name": "read_source",
                        "arguments": '{"file_path":"app.py","line_start":1,"line_end":1}',
                    },
                }],
                usage={"total_tokens": 4},
            ),
            LLMResponse(
                content="",
                tool_calls=[{
                    "id": "final-1",
                    "function": {
                        "name": "FinalizeFinding",
                        "arguments": (
                            '{"id":"candidate-1","title":"Unsafe input","severity":"high",'
                            '"vulnerability_type":"xss","description":"Untrusted input reaches a sink",'
                            '"file_path":"app.py","line_start":1,"line_end":1,"verdict":"potential",'
                            '"confidence":0.8,"evidence_bundle":{"items":[{"type":"code_snippet",'
                            '"summary":"request value"}],"gaps":[]}}'
                        ),
                    },
                }],
                usage={"total_tokens": 7},
            ),
        ]
    )

    result = asyncio.run(
        ReActFindingReviewer(
            llm,
            project_path=str(tmp_path),
            surface_graph={"nodes": [], "edges": []},
            threat_model={},
            max_turns=4,
            checkpoint_sink=lambda task, checkpoint: checkpoints.append(checkpoint),
        ).review({
            "id": "candidate-1",
            "title": "Unsafe input",
            "severity": "high",
            "vulnerability_type": "xss",
            "description": "Untrusted input reaches a sink",
            "file_path": "app.py",
            "line_start": 1,
            "line_end": 1,
        })
    )

    assert result.status == "completed"
    assert result.output["verdict"] == "potential"
    assert result.tool_records[0]["tool_name"] == "read_source"
    assert result.task.turn_count == 2
    assert any(item["reason"] == "tool_completed" for item in checkpoints)
    assert any(item["reason"] == "turn_completed" for item in checkpoints)
    tool_messages = [
        message
        for batch in llm.messages_seen
        for message in batch
        if message.get("role") == "tool"
    ]
    assert tool_messages[0]["tool_call_id"] == "read-1"


def test_react_reviewer_forces_finalize_after_evidence_budget(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("value = request.args['q']\n", encoding="utf-8")

    class BudgetAwareLLM:
        provider = "deepseek"
        model = "test-model"

        def __init__(self):
            self.requests = []
            self.call_count = 0

        async def chat(self, messages, *, tools=None, **kwargs):
            self.requests.append({"tools": tools, "options": kwargs})
            self.call_count += 1
            if tools is None:
                return LLMResponse(
                    content=json.dumps({
                        "terminal_action": "FinalizeFinding",
                        "output": {
                            "id": "model-mutated-id",
                            "title": "Model title",
                            "severity": "high",
                            "vulnerability_type": "different_type",
                            "description": "Static evidence supports a potential issue.",
                            "file_path": "../outside.py",
                            "line_start": 999,
                            "line_end": 999,
                            "verdict": "potential",
                            "confidence": 0.76,
                            "evidence_bundle": {
                                "items": [{"type": "code_snippet", "summary": "source inspected"}],
                                "gaps": ["dynamic validation pending"],
                            },
                        },
                    }),
                    usage={"total_tokens": 5},
                )
            tool_names = [
                item.get("function", {}).get("name")
                for item in (tools or [])
            ]
            if tool_names == ["FinalizeFinding"]:
                arguments = {
                    "id": "model-mutated-id",
                    "title": "Model title",
                    "severity": "high",
                    "vulnerability_type": "different_type",
                    "description": "Static evidence supports a potential issue.",
                    "file_path": "../outside.py",
                    "line_start": 999,
                    "line_end": 999,
                    "verdict": "potential",
                    "confidence": 0.76,
                    "evidence_bundle": {
                        "items": [{"type": "code_snippet", "summary": "source inspected"}],
                        "gaps": ["dynamic validation pending"],
                    },
                }
                return LLMResponse(
                    content="",
                    tool_calls=[{
                        "id": "final-budget",
                        "function": {
                            "name": "FinalizeFinding",
                            "arguments": json.dumps(arguments),
                        },
                    }],
                    usage={"total_tokens": 5},
                )
            line_end = self.call_count
            return LLMResponse(
                content="collect evidence",
                tool_calls=[{
                    "id": f"read-{self.call_count}",
                    "function": {
                        "name": "read_source",
                        "arguments": json.dumps({
                            "file_path": "app.py",
                            "line_start": 1,
                            "line_end": line_end,
                        }),
                    },
                }],
                usage={"total_tokens": 3},
            )

    llm = BudgetAwareLLM()
    result = asyncio.run(ReActFindingReviewer(
        llm,
        project_path=str(tmp_path),
        max_turns=7,
    ).review({
        "id": "candidate-immutable",
        "title": "Original title",
        "severity": "high",
        "vulnerability_type": "xss",
        "description": "Original description",
        "file_path": "app.py",
        "line_start": 1,
        "line_end": 1,
        "confidence": 0.7,
        "evidence": [],
    }))

    assert result.status == "completed"
    assert result.task.turn_count == 5
    assert result.output["id"] == "candidate-immutable"
    assert result.output["file_path"] == "app.py"
    assert result.output["vulnerability_type"] == "xss"
    assert result.output["review_metadata"]["completion_mode"] == "validated_llm_finalize"
    assert any(request["tools"] is None for request in llm.requests)
    assert not any(request["options"].get("tool_choice") for request in llm.requests)


def test_react_reviewer_returns_explicit_degraded_result(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("dangerous(value)\n", encoding="utf-8")
    llm = MockLLMService(responses=[
        LLMResponse(content="still thinking"),
        LLMResponse(content="still thinking"),
    ])

    result = asyncio.run(ReActFindingReviewer(
        llm,
        project_path=str(tmp_path),
        max_turns=2,
    ).review({
        "id": "candidate-degraded",
        "title": "Candidate",
        "severity": "high",
        "vulnerability_type": "command_injection",
        "description": "Candidate description",
        "file_path": "app.py",
        "line_start": 1,
        "line_end": 1,
        "confidence": 0.8,
        "evidence": [{"type": "static", "summary": "pattern matched"}],
    }))

    assert result.status == "degraded"
    assert result.output["verdict"] == "unconfirmed"
    assert result.output["confidence"] <= 0.69
    assert result.output["review_metadata"]["completion_mode"] == "harness_degraded"
    assert result.output["evidence_bundle"]["gaps"]


def test_verification_react_collects_controlled_evidence_and_finalizes(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("value = request.args['q']\n", encoding="utf-8")

    class ScriptedProvider:
        provider = "deepseek"
        model = "test-model"

        def __init__(self):
            self.calls = 0

        async def chat(self, messages, *, tools=None, **kwargs):
            del messages, tools
            self.calls += 1
            if self.calls == 1:
                return LLMResponse(content="", tool_calls=[{
                    "id": "inspect-1",
                    "function": {"name": "inspect_finding", "arguments": "{}"},
                }])
            if self.calls == 2:
                return LLMResponse(content="", tool_calls=[{
                    "id": "static-1",
                    "function": {"name": "run_static_verification", "arguments": "{}"},
                }])
            if self.calls == 3:
                return LLMResponse(content="", tool_calls=[{
                    "id": "dynamic-1",
                    "function": {"name": "run_dynamic_verification", "arguments": "{}"},
                }])
            return LLMResponse(content="", tool_calls=[{
                "id": "final-1",
                "function": {
                    "name": "FinalizeVerification",
                    "arguments": json.dumps({
                        "finding_id": "model-mutated",
                        "verification_status": "verified",
                        "verification_predicate": "The candidate source location remains present.",
                        "confidence": 0.91,
                    }),
                },
            }])

    class Verifier:
        async def _static_verification(self, project_path, finding):
            return VerificationEvidence(
                evidence_type="static",
                description="source location present",
                success=True,
                data={"file_path": finding["file_path"]},
            )

        async def _dynamic_verification(self, project_path, finding):
            return VerificationEvidence(
                "dynamic",
                "positive and negative controls passed",
                True,
                {"positive_control": True, "negative_control": True},
                predicate="both controls pass",
                outcome="supported",
            )

        async def _fuzzing_verification(self, project_path, finding):
            return VerificationEvidence("fuzzing", "unavailable", False, {"error": "Docker unavailable"})

    result = asyncio.run(ReActVerificationReviewer(
        ScriptedProvider(),
        verifier=Verifier(),
        project_path=str(tmp_path),
        max_turns=6,
    ).review({
        "id": "finding-immutable",
        "title": "Unsafe input",
        "severity": "high",
        "vulnerability_type": "xss",
        "file_path": "app.py",
        "line_start": 1,
        "line_end": 1,
    }))

    assert result.status == "completed"
    assert result.output["finding_id"] == "finding-immutable"
    assert result.output["verification_status"] == "verified"
    assert result.output["review_metadata"]["successful_tool_calls"] == 2
    assert result.tool_records[0]["tool_name"] == "inspect_finding"


def test_verification_react_downgrades_runtime_finding_without_dynamic_predicate(tmp_path):
    (tmp_path / "app.py").write_text("element.innerHTML = user_input\n", encoding="utf-8")

    class Provider:
        provider = "deepseek"
        model = "test-model"

        def __init__(self):
            self.calls = 0

        async def chat(self, messages, *, tools=None, **kwargs):
            del messages, tools, kwargs
            self.calls += 1
            if self.calls == 1:
                return LLMResponse(content="", tool_calls=[{
                    "id": "static",
                    "function": {"name": "run_static_verification", "arguments": "{}"},
                }])
            return LLMResponse(content="", tool_calls=[{
                "id": "final",
                "function": {
                    "name": "FinalizeVerification",
                    "arguments": json.dumps({
                        "finding_id": "xss-1",
                        "verification_status": "verified",
                        "verification_predicate": "Untrusted input reaches innerHTML",
                        "evidence_bundle": {"items": [{"type": "static"}], "gaps": []},
                    }),
                },
            }])

    class Verifier:
        async def _static_verification(self, project_path, finding):
            return VerificationEvidence(
                "static", "indicator present", True, {},
                predicate="indicator remains", outcome="supported",
            )

        async def _dynamic_verification(self, project_path, finding):
            raise AssertionError("provider did not request dynamic verification")

        async def _fuzzing_verification(self, project_path, finding):
            raise AssertionError("provider did not request fuzzing verification")

    result = asyncio.run(ReActVerificationReviewer(
        Provider(), verifier=Verifier(), project_path=str(tmp_path), max_turns=4,
    ).review({
        "id": "xss-1",
        "severity": "high",
        "vulnerability_type": "xss",
        "file_path": "app.py",
        "line_start": 1,
        "line_end": 1,
    }))

    assert result.output["verification_status"] == "needs_evidence"
    assert any("run_dynamic_verification" in gap for gap in result.output["evidence_bundle"]["gaps"])


def test_verification_react_binds_static_harness_evidence_over_model_needs_evidence():
    candidate = {
        "id": "secret-alias-1",
        "severity": "high",
        "vulnerability_type": "hardcoded_secrets",
        "file_path": "config.py",
        "line_start": 1,
        "line_end": 1,
        "confidence": 0.8,
    }
    records = [{
        "allowed": True,
        "status": "completed",
        "tool_name": "run_static_verification",
        "output": {
            "success": True,
            "available": True,
            "predicate": "The secret literal remains in the target source location",
            "outcome": "supported",
            "data": {"can_confirm_statically": True},
        },
    }]

    status, output = ReActVerificationReviewer._bind(
        candidate,
        "completed",
        {
            "finding_id": "model-mutated",
            "verification_status": "needs_evidence",
            "verification_predicate": "",
            "evidence_bundle": {"items": [], "gaps": ["model uncertainty"]},
        },
        records,
        None,
    )

    assert status == "completed"
    assert output["finding_id"] == "secret-alias-1"
    assert output["verification_status"] == "static_only"
    assert output["verification_predicate"] == records[0]["output"]["predicate"]
    assert output["evidence_bundle"]["gaps"]
    assert output["review_metadata"]["canonical_vulnerability_type"] == "secret_leak"
    assert FinalizeVerificationContract().validate({
        "finding_id": "secret-alias-1",
        "verification_status": "needs_evidence",
        "verification_predicate": "predicate",
    }).valid is True


def test_finding_review_requires_relevant_semantic_trace_for_confirmed_path():
    candidate = {
        "id": "sql-path-1",
        "title": "Dynamic SQL",
        "severity": "high",
        "vulnerability_type": "sql_injection",
        "description": "Request input reaches SQL",
        "file_path": "service.py",
        "line_start": 2,
        "line_end": 2,
        "evidence": [{"type": "code_snippet"}],
    }
    model_output = {
        **candidate,
        "verdict": "confirmed",
        "evidence_bundle": {"items": [{"type": "source_path"}], "gaps": []},
    }
    read_record = {
        "allowed": True,
        "status": "completed",
        "tool_name": "read_source",
        "output": {"file_path": "service.py"},
    }
    unrelated_trace = {
        "allowed": True,
        "status": "completed",
        "tool_name": "trace_python_flow",
        "output": {"paths": [{"nodes": [{"file_path": "other.py"}]}]},
    }
    relevant_trace = {
        "allowed": True,
        "status": "completed",
        "tool_name": "trace_python_flow",
        "output": {"paths": [{"nodes": [{"file_path": "service.py"}]}]},
    }

    _, without_trace = ReActFindingReviewer._bind_review_result(
        candidate, None, "completed", model_output, [read_record], None,
    )
    _, with_unrelated = ReActFindingReviewer._bind_review_result(
        candidate, None, "completed", model_output, [read_record, unrelated_trace], None,
    )
    _, with_relevant = ReActFindingReviewer._bind_review_result(
        candidate, None, "completed", model_output, [read_record, relevant_trace], None,
    )

    assert without_trace["verdict"] == "potential"
    assert with_unrelated["verdict"] == "potential"
    assert with_relevant["verdict"] == "confirmed"
    assert with_relevant["review_metadata"]["semantic_traces"] == 1
