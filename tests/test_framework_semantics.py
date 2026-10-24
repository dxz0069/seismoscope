import asyncio

from core.tool_fabric import ArtifactStore, ToolGateway, ToolRequest, build_source_registry
from core.tool_fabric.framework_semantics import analyze_framework_semantics


def test_python_ast_extracts_fastapi_route_guard_input_sink_and_risk_path(tmp_path):
    (tmp_path / "api.py").write_text(
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI()\n"
        "def require_user(): pass\n"
        "@app.get('/search')\n"
        "async def search(q: str, user=Depends(require_user)):\n"
        "    return cursor.execute(f\"SELECT * FROM users WHERE name='{q}'\")\n",
        encoding="utf-8",
    )

    report = analyze_framework_semantics(tmp_path)
    kinds = {item.semantic_type for item in report.observations}

    assert report.to_dict()["contract"] == "vibe-sec.framework-semantics.v1"
    assert {"route", "untrusted_input", "authorization_guard", "sql_sink"}.issubset(kinds)
    assert report.risk_paths[0]["framework"] == "fastapi"
    assert report.risk_paths[0]["guard_status"] == "observed"
    assert report.risk_paths[0]["binding"] == "same Python function"


def test_tree_sitter_extracts_express_spring_and_go_framework_semantics(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import express from 'express';\n"
        "const app = express();\n"
        "app.get('/users', requireRole('admin'), async (req, res) => {\n"
        "  const id = req.query.id;\n"
        "  return res.json(await db.query(`SELECT * FROM users WHERE id=${id}`));\n"
        "});\n",
        encoding="utf-8",
    )
    (tmp_path / "UserController.java").write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "class UserController {\n"
        "  @GetMapping(\"/users\")\n"
        "  @PreAuthorize(\"hasRole('ADMIN')\")\n"
        "  Object users(@RequestParam String q) { return jdbcTemplate.query(q); }\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "main.go").write_text(
        "package main\n"
        "import (\"net/http\"; \"os/exec\")\n"
        "func main() { http.HandleFunc(\"/run\", run) }\n"
        "func run(w http.ResponseWriter, r *http.Request) {\n"
        "  value := r.FormValue(\"cmd\")\n"
        "  exec.Command(value).Run()\n"
        "}\n",
        encoding="utf-8",
    )

    report = analyze_framework_semantics(tmp_path)
    frameworks = set(report.to_dict()["frameworks"])
    by_framework = {}
    for item in report.observations:
        by_framework.setdefault(item.framework, set()).add(item.semantic_type)

    assert {"express", "spring", "go-http"}.issubset(frameworks)
    assert {"route", "untrusted_input", "sql_sink"}.issubset(by_framework["express"])
    assert {"route", "authorization_guard", "untrusted_input", "sql_sink"}.issubset(by_framework["spring"])
    assert {"route", "untrusted_input", "code_execution_sink"}.issubset(by_framework["go-http"])
    assert report.coverage["parse_failures"] == []


def test_framework_semantics_is_agent_tool_with_artifact_and_scope(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.get('/hello')\n"
        "def hello(): return request.args.get('name')\n",
        encoding="utf-8",
    )
    gateway = ToolGateway(
        build_source_registry(),
        project_root=str(tmp_path),
        artifact_store=ArtifactStore(str(tmp_path / "artifacts"), session_id="framework"),
    )

    result = asyncio.run(gateway.execute(ToolRequest(
        "inspect_framework_semantics", {"file_path": "app.py", "framework": "flask"},
    )))

    assert result.status.value == "completed"
    assert result.output["frameworks"] == ["flask"]
    assert result.output["coverage"]["parsed_files"] == ["app.py"]
    assert result.artifacts[0].artifact_type == "framework_semantic_report"
