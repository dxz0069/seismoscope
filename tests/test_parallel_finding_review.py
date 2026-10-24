"""Candidate reviews must have isolated contexts and tool audit records."""

import asyncio
import json

from agents.audit_agent import AuditAgent, AuditState, CandidateCase
from core.audit.review_budget import SharedReviewBudget
from core.agents.base import Severity
from core.llm_service import LLMResponse


class CandidateAwareProvider:
    provider = "deepseek"
    model = "test-model"

    async def chat(self, messages, *, tools=None, **kwargs):
        del tools, kwargs
        prompt = next(
            json.loads(message.content)
            for message in messages
            if message.role == "user" and '"candidate"' in message.content
        )
        candidate = prompt["candidate"]
        if not any(message.role == "tool" for message in messages):
            return LLMResponse(content="", tool_calls=[{
                "id": f"read-{candidate['id']}",
                "function": {
                    "name": "read_source",
                    "arguments": json.dumps({
                        "file_path": candidate["file_path"],
                        "line_start": 1,
                        "line_end": 2,
                    }),
                },
            }])
        return LLMResponse(content="", tool_calls=[{
            "id": f"final-{candidate['id']}",
            "function": {
                "name": "FinalizeFinding",
                "arguments": json.dumps({
                    **candidate,
                    "verdict": "potential",
                    "evidence_bundle": {
                        "items": [{"type": "code_snippet", "summary": candidate["file_path"]}],
                        "gaps": ["Runtime validation pending"],
                    },
                }),
            },
        }])


def test_parallel_reviews_do_not_share_tool_cache_or_records(tmp_path):
    (tmp_path / "a.py").write_text("dangerous(a)\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("dangerous(b)\n", encoding="utf-8")
    agent = AuditAgent(llm_service=CandidateAwareProvider())
    agent.audit_state = AuditState(candidates=[
        CandidateCase(
            id="candidate-a",
            vulnerability_type="command_injection",
            severity=Severity.HIGH,
            file_path="a.py",
            line_start=1,
            line_end=1,
            description="Candidate A",
        ),
        CandidateCase(
            id="candidate-b",
            vulnerability_type="command_injection",
            severity=Severity.HIGH,
            file_path="b.py",
            line_start=1,
            line_end=1,
            description="Candidate B",
        ),
    ])

    stats = asyncio.run(agent._react_review_candidates(str(tmp_path), {
        "react_review_limit": 2,
        "react_review_concurrency": 2,
    }))

    assert stats["completed"] == 2
    for candidate in agent.audit_state.candidates:
        review = next(item for item in candidate.evidence if item.get("type") == "react_finding_review")
        assert len(review["tool_records"]) == 1
        assert review["tool_records"][0]["output"]["file_path"] == candidate.file_path


def test_shared_review_budget_caps_reviews_across_agent_instances(tmp_path):
    (tmp_path / "a.py").write_text("dangerous(a)\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("dangerous(b)\n", encoding="utf-8")
    budget = SharedReviewBudget(limit=1)

    def make_agent(candidate_id, file_path):
        agent = AuditAgent(llm_service=CandidateAwareProvider())
        agent.audit_state = AuditState(candidates=[CandidateCase(
            id=candidate_id,
            vulnerability_type="command_injection",
            severity=Severity.HIGH,
            file_path=file_path,
            line_start=1,
            line_end=1,
            description=candidate_id,
        )])
        return agent

    first = make_agent("candidate-a", "a.py")
    second = make_agent("candidate-b", "b.py")

    first_stats = asyncio.run(first._react_review_candidates(str(tmp_path), {
        "react_review_limit": 1,
        "_react_review_budget": budget,
    }))
    second_stats = asyncio.run(second._react_review_candidates(str(tmp_path), {
        "react_review_limit": 1,
        "_react_review_budget": budget,
    }))

    assert first_stats["completed"] == 1
    assert second_stats["total"] == 0
    assert second_stats["budget_skipped"] == 1
    assert budget.to_dict()["limit"] == 1
    assert budget.to_dict()["claimed"] == 1
    assert budget.to_dict()["remaining"] == 0


def test_shared_review_budget_selects_global_highest_risk_candidates():
    async def select():
        budget = SharedReviewBudget(limit=2, expected_lanes=3)
        selected = await asyncio.gather(
            budget.select_for_lane("web_audit", [{
                "id": "web-medium", "severity": "medium", "confidence": 0.99, "order": 0,
            }]),
            budget.select_for_lane("agent_audit", [{
                "id": "agent-high", "severity": "high", "confidence": 0.30, "order": 0,
            }]),
            budget.select_for_lane("mcp_audit", [{
                "id": "mcp-critical", "severity": "critical", "confidence": 0.10, "order": 0,
            }]),
        )
        return budget, selected

    budget, selected = asyncio.run(select())

    assert selected == [set(), {"agent-high"}, {"mcp-critical"}]
    assert budget.to_dict()["selection_mode"] == "global_priority"
    assert budget.to_dict()["claimed"] == 2
