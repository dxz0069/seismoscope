"""Tests for Agent-led cross-file candidate discovery."""

import asyncio
import json

from core.audit.react_discovery import ReActAuditDiscovery
from core.llm_service import LLMResponse


class DiscoveryProvider:
    provider = "deepseek"
    model = "test-model"

    def __init__(self):
        self.calls = 0

    async def chat(self, messages, *, tools=None, **kwargs):
        del messages, tools, kwargs
        self.calls += 1
        calls = {
            1: ("load_audit_guidance", {
                "lane": "web_audit", "vulnerability_type": "sql_injection", "language": "python",
            }),
            2: ("list_source_files", {"glob": "*.py"}),
            3: ("search_code", {"pattern": "load_user", "max_results": 20}),
            4: ("read_source", {"file_path": "service.py", "line_start": 1, "line_end": 20}),
            5: ("trace_python_flow", {
                "file_path": "route.py", "symbol": "handler", "max_depth": 3,
            }),
        }
        if self.calls in calls:
            name, arguments = calls[self.calls]
            return LLMResponse(content="", tool_calls=[{
                "id": f"tool-{self.calls}",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }])
        return LLMResponse(content="", tool_calls=[{
            "id": "final-discovery",
            "function": {
                "name": "FinalizeAuditDiscovery",
                "arguments": json.dumps({
                    "lane": "web_audit",
                    "summary": "Traced request input into a dynamically formatted SQL query.",
                    "coverage": {
                        "files_examined": ["route.py", "service.py"],
                        "entry_points_examined": ["route.handler"],
                        "hypotheses_examined": [],
                        "gaps": ["No runtime database was started"],
                    },
                    "candidates": [{
                        "title": "User identifier reaches formatted SQL",
                        "severity": "high",
                        "vulnerability_type": "sql_injection",
                        "description": "The route passes request input to a formatted SQL query.",
                        "file_path": "service.py",
                        "line_start": 2,
                        "line_end": 2,
                        "confidence": 0.82,
                        "evidence_bundle": {
                            "items": [{"type": "source_path", "summary": "route -> load_user -> run"}],
                            "gaps": ["Runtime validation pending"],
                        },
                    }],
                }),
            },
        }])


def test_discovery_explores_cross_file_context_and_binds_artifacts(tmp_path):
    (tmp_path / "service.py").write_text(
        "def load_user(cursor, user_id):\n"
        "    return cursor.execute(f'SELECT * FROM users WHERE id={user_id}')\n",
        encoding="utf-8",
    )
    (tmp_path / "route.py").write_text(
        "from service import load_user\n"
        "def handler(request, cursor):\n"
        "    return load_user(cursor, request.args['id'])\n",
        encoding="utf-8",
    )

    result = asyncio.run(ReActAuditDiscovery(
        DiscoveryProvider(),
        project_path=str(tmp_path),
        lane="web_audit",
        max_turns=8,
    ).discover())

    assert result.status == "completed"
    assert len(result.candidates) == 1
    assert result.candidates[0]["vulnerability_type"] == "sql_injection"
    assert result.candidates[0]["status"] == "needs_evidence"
    assert result.candidates[0]["evidence_bundle"]["artifact_refs"]
    assert result.coverage["source_tool_calls"] == 3
    assert result.coverage["semantic_budget_met"] is True
    assert result.coverage["knowledge_budget_met"] is True
    assert "knowledge_base/source_audit_methodology.md" in result.coverage["guidance_documents_loaded"]
    semantic = next(
        item for item in result.candidates[0]["evidence_bundle"]["items"]
        if item.get("type") == "semantic_source_path"
    )
    assert semantic["cross_file"] is True
    assert semantic["sink_observations"][0]["kind"] == "sql_execution"


def test_discovery_degrades_without_real_source_exploration(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")

    class EarlyFinalProvider:
        provider = "deepseek"
        model = "test-model"

        async def chat(self, messages, *, tools=None, **kwargs):
            del messages, tools, kwargs
            return LLMResponse(content="", tool_calls=[{
                "id": "early-final",
                "function": {
                    "name": "FinalizeAuditDiscovery",
                    "arguments": json.dumps({
                        "lane": "web_audit",
                        "summary": "No issues",
                        "coverage": {"files_examined": [], "gaps": []},
                        "candidates": [],
                    }),
                },
            }])

    result = asyncio.run(ReActAuditDiscovery(
        EarlyFinalProvider(),
        project_path=str(tmp_path),
        lane="web_audit",
        max_turns=3,
    ).discover())

    assert result.status == "degraded"
    assert result.candidates == []
    assert result.coverage["gaps"]


def test_discovery_degrades_when_python_candidate_has_no_semantic_trace(tmp_path):
    (tmp_path / "app.py").write_text(
        "def handler(request, cursor):\n"
        "    return cursor.execute(request.args['query'])\n",
        encoding="utf-8",
    )

    class ReadOnlyProvider:
        provider = "deepseek"
        model = "test-model"

        def __init__(self):
            self.calls = 0

        async def chat(self, messages, *, tools=None, **kwargs):
            del messages, tools, kwargs
            self.calls += 1
            if self.calls == 1:
                return LLMResponse(content="", tool_calls=[{
                    "id": "search",
                    "function": {"name": "search_code", "arguments": '{"pattern":"execute"}'},
                }])
            if self.calls == 2:
                return LLMResponse(content="", tool_calls=[{
                    "id": "read",
                    "function": {
                        "name": "read_source",
                        "arguments": '{"file_path":"app.py","line_start":1,"line_end":2}',
                    },
                }])
            return LLMResponse(content="", tool_calls=[{
                "id": "final",
                "function": {
                    "name": "FinalizeAuditDiscovery",
                    "arguments": json.dumps({
                        "lane": "web_audit",
                        "summary": "Candidate found",
                        "coverage": {"files_examined": ["app.py"], "gaps": []},
                        "candidates": [{
                            "title": "Dynamic SQL",
                            "severity": "high",
                            "vulnerability_type": "sql_injection",
                            "description": "Request query reaches execute",
                            "file_path": "app.py",
                            "line_start": 2,
                            "line_end": 2,
                            "evidence_bundle": {
                                "items": [{"type": "source_path"}], "gaps": [],
                            },
                        }],
                    }),
                },
            }])

    result = asyncio.run(ReActAuditDiscovery(
        ReadOnlyProvider(), project_path=str(tmp_path), lane="web_audit", max_turns=5,
    ).discover())

    assert result.status == "degraded"
    assert result.candidates == []
    assert result.coverage["semantic_trace_required"] is True
    assert result.coverage["semantic_budget_met"] is False
    assert any("semantically trace" in gap for gap in result.coverage["gaps"])


def test_discovery_rejects_candidate_with_out_of_range_location(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    discovery = ReActAuditDiscovery(
        DiscoveryProvider(), project_path=str(tmp_path), lane="web_audit",
    )
    candidate = discovery._bind_candidate({
        "title": "Invalid location",
        "severity": "high",
        "vulnerability_type": "sql_injection",
        "description": "Invalid",
        "file_path": "app.py",
        "line_start": 99,
        "line_end": 99,
        "evidence_bundle": {"items": [{"type": "source_path"}], "gaps": []},
    }, 1, [{
        "execution_id": "read-1",
        "tool_name": "read_source",
        "output": {"file_path": "app.py"},
        "artifacts": [],
    }])

    assert candidate is None


def test_discovery_never_binds_audit_guidance_as_candidate_evidence(tmp_path):
    (tmp_path / "app.py").write_text("dangerous()\n", encoding="utf-8")
    discovery = ReActAuditDiscovery(
        DiscoveryProvider(), project_path=str(tmp_path), lane="web_audit",
    )
    records = [{
        "execution_id": "guidance-1",
        "tool_name": "load_audit_guidance",
        "output": {"documents": [{"path": "app.py", "excerpt": "dangerous()"}]},
        "artifacts": [{"artifact_id": "guidance-artifact"}],
    }, {
        "execution_id": "read-1",
        "tool_name": "read_source",
        "output": {"file_path": "app.py", "content": "1: dangerous()"},
        "artifacts": [{"artifact_id": "source-artifact"}],
    }]

    candidate = discovery._bind_candidate({
        "title": "Dangerous call",
        "severity": "high",
        "vulnerability_type": "command_injection",
        "description": "A dangerous call exists",
        "file_path": "app.py",
        "line_start": 1,
        "line_end": 1,
        "evidence_bundle": {"items": [{"type": "source_excerpt"}], "gaps": []},
    }, 1, records)

    assert candidate is not None
    assert candidate["evidence_bundle"]["artifact_refs"] == ["source-artifact"]
    assert candidate["evidence_bundle"]["tool_execution_ids"] == ["read-1"]


def test_discovery_accepts_javascript_candidate_only_with_relevant_semantic_trace(tmp_path):
    (tmp_path / "service.js").write_text(
        "export function loadUser(db, id) {\n  return db.query(`select ${id}`);\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "route.js").write_text(
        "import { loadUser } from './service.js';\n"
        "export function handler(req, db) { return loadUser(db, req.query.id); }\n",
        encoding="utf-8",
    )

    class JavaScriptProvider:
        provider = "deepseek"
        model = "test-model"

        def __init__(self):
            self.calls = 0

        async def chat(self, messages, *, tools=None, **kwargs):
            del messages, tools, kwargs
            self.calls += 1
            calls = {
                1: ("load_audit_guidance", {
                    "lane": "web_audit", "vulnerability_type": "sql_injection", "language": "javascript",
                }),
                2: ("list_source_files", {"glob": "*.js"}),
                3: ("read_source", {"file_path": "service.js", "line_start": 1, "line_end": 3}),
                4: ("trace_javascript_flow", {"file_path": "route.js", "symbol": "handler"}),
            }
            if self.calls in calls:
                name, arguments = calls[self.calls]
                return LLMResponse(content="", tool_calls=[{
                    "id": f"js-{self.calls}",
                    "function": {"name": name, "arguments": json.dumps(arguments)},
                }])
            return LLMResponse(content="", tool_calls=[{
                "id": "js-final",
                "function": {
                    "name": "FinalizeAuditDiscovery",
                    "arguments": json.dumps({
                        "lane": "web_audit",
                        "summary": "Cross-file SQL path",
                        "coverage": {"files_examined": ["route.js", "service.js"], "gaps": []},
                        "candidates": [{
                            "title": "Dynamic SQL",
                            "severity": "high",
                            "vulnerability_type": "sql_injection",
                            "description": "Request id reaches db.query",
                            "file_path": "service.js",
                            "line_start": 2,
                            "line_end": 2,
                            "evidence_bundle": {"items": [{"type": "source_path"}], "gaps": []},
                        }],
                    }),
                },
            }])

    result = asyncio.run(ReActAuditDiscovery(
        JavaScriptProvider(), project_path=str(tmp_path), lane="web_audit", max_turns=7,
    ).discover())

    assert result.status == "completed"
    assert len(result.candidates) == 1
    assert result.coverage["semantic_budget_met"] is True
    assert result.coverage["semantic_files_examined"] == ["route.js", "service.js"]
    assert any(
        item.get("type") == "semantic_source_path"
        for item in result.candidates[0]["evidence_bundle"]["items"]
    )
