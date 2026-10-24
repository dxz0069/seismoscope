import asyncio

from agents.surface_agent import SurfaceAgent
from core.harness.models import RuntimeSurfaceGraph
from core.surface.runtime_surface import (
    BrowserSink,
    CodeBlock,
    EntryType,
    ExternalContentInput,
    PageEntry,
    RuntimeSurface,
    RuntimeSurfaceBuilder,
    StorageAsset,
    _walk_ts,
)
from core.surface.threat_model import RuntimeThreatModelAnalyzer


def _build_surface(tmp_path):
    (tmp_path / "agent.ts").write_text(
        "import { execSync } from 'node:child_process';\n"
        "const systemPrompt = 'Summarize the supplied content';\n"
        "async function runAgent(response: Response) {\n"
        "  const externalInstructions = await response.text();\n"
        "  const result = await client.responses.create({\n"
        "    input: systemPrompt + externalInstructions,\n"
        "    tools: [{ type: 'mcp' }]\n"
        "  });\n"
        "  preview.innerHTML = externalInstructions;\n"
        "  localStorage.setItem('session_token', externalInstructions);\n"
        "  return result;\n"
        "}\n"
        "server.registerTool('deploy', { description: 'Deploy a release' }, async () => {\n"
        "  return execSync('deploy-current-release');\n"
        "});\n",
        encoding="utf-8",
    )
    workflow = tmp_path / ".github" / "workflows" / "triage.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "name: triage\n"
        "on: [issues]\n"
        "permissions:\n"
        "  contents: write\n"
        "jobs:\n"
        "  apply-label:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: unsafe command\n"
        "        env:\n"
        "          TITLE: ${{ github.event.issue.title }}\n"
        "          TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        "        run: echo \"$TITLE\" | sh\n",
        encoding="utf-8",
    )
    return asyncio.run(RuntimeSurfaceBuilder(str(tmp_path)).build())


def test_composite_surface_extracts_first_class_runtime_objects(tmp_path):
    surface = _build_surface(tmp_path)

    assert surface.prompt_configs[0].name == "systemPrompt"
    assert surface.model_invocations[0].tool_enabled is True
    assert any(item.name == "deploy" and item.capability_type == "tool" for item in surface.mcp_capabilities)
    assert any(item.sink_type == "innerHTML" for item in surface.browser_sinks)
    assert any(item.name == "session_token" and item.sensitive for item in surface.storage_assets)
    assert any(item.source_type == "network_response" for item in surface.external_content_inputs)
    assert any(item.node_type == "job" and item.untrusted_inputs for item in surface.workflow_nodes)
    assert surface.metadata["extraction_coverage"]["files_parsed"] == 2


def test_tree_sitter_walk_handles_deep_syntax_trees_without_recursion():
    class Node:
        def __init__(self, children=()):
            self.children = children

    root = Node()
    for _ in range(2_000):
        root = Node((root,))

    assert len(list(_walk_ts(root))) == 2_001


def test_runtime_graph_has_stable_source_grounded_security_edges(tmp_path):
    surface = _build_surface(tmp_path)
    first = RuntimeSurfaceGraph.from_surface(surface)
    second = RuntimeSurfaceGraph.from_surface(surface)

    assert first.to_dict() == second.to_dict()
    node_ids = set(first.node_ids())
    assert len(node_ids) == len(first.nodes)
    assert all(edge.source in node_ids and edge.target in node_ids for edge in first.edges)
    assert all(edge.attributes.get("security_meaning") for edge in first.edges)
    relations = {edge.relation for edge in first.edges}
    assert {"influences", "supplies_instructions", "can_invoke", "renders_at", "accesses"} <= relations
    assert first.metadata["source_grounded_edges"] == len(first.edges)

    for node in first.nodes:
        if node.node_type != "external_actor":
            provenance = node.attributes["provenance"]
            assert provenance["file_path"]
            assert provenance["line_start"] >= 1


def test_runtime_surface_extracts_openapi_operations_and_binds_handlers(tmp_path):
    api_views = tmp_path / "api_views"
    api_views.mkdir()
    (api_views / "users.py").write_text(
        "def get_user(username):\n"
        "    return username\n\n"
        "def create_user():\n"
        "    return 'created'\n",
        encoding="utf-8",
    )
    spec_dir = tmp_path / "openapi_specs"
    spec_dir.mkdir()
    (spec_dir / "openapi.yml").write_text(
        "openapi: 3.0.3\n"
        "security:\n"
        "  - bearerAuth: []\n"
        "paths:\n"
        "  /users/{username}:\n"
        "    parameters:\n"
        "      - name: username\n"
        "        in: path\n"
        "        required: true\n"
        "        schema:\n"
        "          type: string\n"
        "    get:\n"
        "      operationId: api_views.users.get_user\n"
        "  /users:\n"
        "    post:\n"
        "      security: []\n"
        "      operationId: api_views.users.create_user\n"
        "      requestBody:\n"
        "        required: true\n"
        "        content:\n"
        "          application/json:\n"
        "            schema:\n"
        "              type: object\n",
        encoding="utf-8",
    )

    surface = asyncio.run(RuntimeSurfaceBuilder(str(tmp_path)).build())
    entries = {(item.method, item.path): item for item in surface.page_entries}

    get_user = entries[("GET", "/users/{username}")]
    assert get_user.file_path == "api_views/users.py"
    assert get_user.handler_function == "get_user"
    assert get_user.authentication_required is True
    assert get_user.authentication_state == "declared"
    assert get_user.parameters == [{
        "name": "username", "in": "path", "required": True, "schema": {"type": "string"},
    }]
    assert entries[("POST", "/users")].authentication_required is False
    assert entries[("POST", "/users")].authentication_state == "declared_public"
    assert {item.name for item in surface.external_content_inputs} >= {
        "request.path.username", "request.body",
    }

    graph = RuntimeSurfaceGraph.from_surface(surface)
    nodes = {node.node_id: node for node in graph.nodes}
    edges = {
        (nodes[edge.source].node_type, nodes[edge.source].label, edge.relation, nodes[edge.target].node_type, nodes[edge.target].label)
        for edge in graph.edges
    }
    assert ("entry_point", "GET /users/{username}", "implemented_by", "code_block", "get_user") in edges
    assert ("entry_point", "GET /users/{username}", "provides", "external_content", "request.path.username") in edges


def test_runtime_graph_connects_unique_cross_file_calls_and_source_ranges():
    surface = RuntimeSurface(
        project_path=".",
        page_entries=[PageEntry(
            path="/search", method="GET", entry_type=EntryType.API_ENDPOINT,
            file_path="routes.py", line_start=2, line_end=5, handler_function="search",
        )],
        code_blocks=[
            CodeBlock(
                block_type="function", name="route_handler", file_path="routes.py",
                line_start=3, line_end=5, calls=["service.search"],
            ),
            CodeBlock(
                block_type="function", name="search", file_path="service.py",
                line_start=10, line_end=20, calls=[],
                contains_user_input=True, contains_dangerous_operations=True,
            ),
        ],
        external_content_inputs=[ExternalContentInput(
            name="request.args", source_type="http_request", expression="request.args['q']",
            file_path="service.py", line_start=12, line_end=12,
        )],
        browser_sinks=[BrowserSink(
            sink_type="innerHTML", expression="panel.innerHTML = query", file_path="service.py",
            line_start=15, line_end=15, input_refs=["query"],
        )],
        storage_assets=[StorageAsset(
            name="searches", storage_type="database", operation="write", file_path="service.py",
            line_start=18, line_end=18,
        )],
    )

    graph = RuntimeSurfaceGraph.from_surface(surface)
    nodes = {node.node_id: node for node in graph.nodes}
    edges = {(nodes[edge.source].node_type, nodes[edge.source].label, edge.relation, nodes[edge.target].node_type, nodes[edge.target].label) for edge in graph.edges}

    assert ("code_block", "route_handler", "calls", "code_block", "search") in edges
    assert ("entry_point", "GET /search", "implemented_by", "code_block", "search") in edges
    assert ("external_content", "request.args", "received_by", "code_block", "search") in edges
    assert ("code_block", "search", "renders_at", "browser_sink", "innerHTML") in edges
    assert ("code_block", "search", "writes", "storage_asset", "database:searches") in edges
    assert graph.metadata["isolated_node_count"] >= 0
    assert graph.metadata["isolated_node_ratio"] >= 0
    assert isinstance(graph.metadata["isolated_nodes_by_type"], dict)


def test_runtime_threat_model_attaches_composite_risks_to_real_paths(tmp_path):
    surface = _build_surface(tmp_path)
    graph = RuntimeSurfaceGraph.from_surface(surface)
    model = RuntimeThreatModelAnalyzer(surface, graph).analyze()
    technique_ids = {item.technique_id for item in model.hypotheses}

    assert "T-INDIRECT-PROMPT-INJECTION" in technique_ids
    assert "T-MCP-AUTHORIZATION" in technique_ids
    assert "T-BROWSER-SINK-INJECTION" in technique_ids
    assert "T-WORKFLOW-PRIVILEGE" in technique_ids
    assert "T-SENSITIVE-STORAGE-ACCESS" in technique_ids

    nodes = {node.node_id: node for node in graph.nodes}
    edge_pairs = {(edge.source, edge.target) for edge in graph.edges}
    for hypothesis in model.hypotheses:
        assert hypothesis.attack_path
        assert all(node_id in nodes for node_id in hypothesis.attack_path)
        assert all(
            (source, target) in edge_pairs
            for source, target in zip(hypothesis.attack_path, hypothesis.attack_path[1:], strict=False)
        )
        assert hypothesis.evidence_predicates

    composite = [
        item for item in model.hypotheses
        if item.technique_id in {
            "T-INDIRECT-PROMPT-INJECTION",
            "T-MCP-AUTHORIZATION",
            "T-BROWSER-SINK-INJECTION",
            "T-WORKFLOW-PRIVILEGE",
            "T-SENSITIVE-STORAGE-ACCESS",
        }
    ]
    assert all(
        any(nodes[node_id].attributes.get("file_path") for node_id in item.source_node_ids)
        or item.technique_id == "T-WORKFLOW-PRIVILEGE"
        for item in composite
    )


def test_workflow_hypothesis_groups_untrusted_child_steps_under_their_job(tmp_path):
    surface = _build_surface(tmp_path)
    graph = RuntimeSurfaceGraph.from_surface(surface)
    model = RuntimeThreatModelAnalyzer(surface, graph).analyze()
    workflow_hypotheses = [
        item for item in model.hypotheses
        if item.technique_id == "T-WORKFLOW-PRIVILEGE"
    ]

    assert len(workflow_hypotheses) == 1
    assert workflow_hypotheses[0].risk_factors["aggregated_workflow_node_count"] == 2


def test_unprotected_entry_requires_runtime_evidence_and_sensitive_operation():
    surface = RuntimeSurface(
        project_path=".",
        page_entries=[
            PageEntry(
                path="/health", method="GET", entry_type=EntryType.API_ENDPOINT,
                file_path="app.py", line_start=1, line_end=1,
            ),
            PageEntry(
                path="/admin/users", method="POST", entry_type=EntryType.API_ENDPOINT,
                file_path="app.py", line_start=10, line_end=10,
            ),
            PageEntry(
                path="/admin/users", method="POST", entry_type=EntryType.API_ENDPOINT,
                file_path="app.py", line_start=20, line_end=20,
                authentication_state="runtime_observed",
            ),
        ],
    )
    model = RuntimeThreatModelAnalyzer(surface, RuntimeSurfaceGraph.from_surface(surface)).analyze()
    entries = [item for item in model.hypotheses if item.technique_id == "T-UNPROTECTED-ENTRY"]

    assert len(entries) == 1
    assert entries[0].attack_path
    assert model.coverage["auth_unknown_entry_count"] == 2


def test_permission_edges_do_not_cross_unrelated_files(tmp_path):
    (tmp_path / "auth.py").write_text(
        "@login_required\n"
        "def account():\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )
    (tmp_path / "ops.py").write_text(
        "def shell_tool(command):\n"
        "    return os.system(command)\n",
        encoding="utf-8",
    )
    surface = asyncio.run(RuntimeSurfaceBuilder(str(tmp_path)).build())
    graph = RuntimeSurfaceGraph.from_surface(surface)
    nodes = {node.node_id: node for node in graph.nodes}

    governed = [
        edge for edge in graph.edges
        if edge.relation == "governed_by" and nodes[edge.source].node_type == "tool"
    ]
    assert governed == []


def test_framework_semantics_projects_spring_and_go_into_runtime_surface(tmp_path):
    (tmp_path / "Controller.java").write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController class Controller {\n"
        "@GetMapping(\"/search\") @PreAuthorize(\"hasRole('USER')\")\n"
        "Object search(@RequestParam String q) { return jdbcTemplate.query(q); }\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "main.go").write_text(
        "package main\nimport (\"net/http\"; \"os/exec\")\n"
        "func main(){ http.HandleFunc(\"/run\", run) }\n"
        "func run(w http.ResponseWriter,r *http.Request){ exec.Command(r.FormValue(\"cmd\")).Run() }\n",
        encoding="utf-8",
    )

    surface = asyncio.run(RuntimeSurfaceBuilder(str(tmp_path)).build())
    graph = RuntimeSurfaceGraph.from_surface(surface)

    assert {item.path for item in surface.page_entries} >= {"/search", "/run"}
    assert any(item.permission_type == "authorization" for item in surface.permission_profiles)
    assert any(item.source_type == "framework_request" for item in surface.external_content_inputs)
    assert any(item.storage_type == "database" for item in surface.storage_assets)
    assert any("process_execution" in item.dangerous_operations for item in surface.tool_profiles)
    assert surface.metadata["framework_semantics"]["coverage"]["parse_failures"] == []
    assert any(node.attributes.get("file_path") == "Controller.java" for node in graph.nodes)


def test_vrtm_graph_enrichment_has_evidence_planes_coverage_and_stable_diff(tmp_path):
    surface = _build_surface(tmp_path)
    first = RuntimeSurfaceGraph.from_surface(surface)
    second = RuntimeSurfaceGraph.from_surface(surface)

    assert first.metadata["schema"] == "vibe-sec.vrtm.graph.v1"
    assert first.metadata["fingerprint"] == second.metadata["fingerprint"]
    assert first.metadata["coverage"]["flow_plane_edge_counts"]["instruction"] > 0
    assert first.metadata["coverage"]["flow_plane_edge_counts"]["authority"] > 0
    assert all(node.evidence.get("level") for node in first.nodes)
    assert all(node.attributes.get("entity_group") for node in first.nodes)
    assert all(edge.semantic_relation and edge.flow_planes for edge in first.edges)
    assert all(edge.evidence.get("level") for edge in first.edges)

    changed = RuntimeSurfaceGraph.from_dict(first.to_dict())
    changed.nodes[0].attributes["review_marker"] = "changed"
    graph_diff = changed.diff(first)
    assert graph_diff["added_nodes"] == []
    assert graph_diff["removed_nodes"] == []
    assert graph_diff["changed_nodes"] == [changed.nodes[0].node_id]
    assert graph_diff["current_fingerprint"] != graph_diff["previous_fingerprint"]


def test_vrtm_threat_hypotheses_and_visualization_expose_method_semantics(tmp_path):
    surface = _build_surface(tmp_path)
    graph = RuntimeSurfaceGraph.from_surface(surface)
    model = RuntimeThreatModelAnalyzer(surface, graph).analyze()
    projection = graph.to_visualization(model.to_dict())

    assert model.version == "0.4"
    assert all(item.flow_planes for item in model.techniques)
    assert all(item.path_pattern for item in model.techniques)
    assert all(item.external_mappings for item in model.techniques)
    assert all(item.flow_planes for item in model.hypotheses)
    assert all(item.control_gaps for item in model.hypotheses)
    assert all(item.risk_factors.get("control_strength") for item in model.hypotheses)
    assert all(item.external_mappings for item in model.hypotheses)
    assert set(projection["views"]) == {"data", "instruction", "authority", "artifact"}
    assert projection["fingerprint"] == graph.metadata["fingerprint"]
    assert projection["coverage"] == graph.metadata["coverage"]
    assert all("semantic_relation" in edge and "evidence" in edge for edge in projection["edges"])


def test_graph_observations_require_evidence_and_update_existing_entities(tmp_path):
    surface = _build_surface(tmp_path)
    graph = RuntimeSurfaceGraph.from_surface(surface)
    sink = next(node for node in graph.nodes if node.node_type == "browser_sink")
    result = graph.apply_observations([
        {
            "id": "obs-runtime-sink-1",
            "target_kind": "node",
            "target_id": sink.node_id,
            "evidence_level": "runtime_observed",
            "source_agent": "verification",
            "source_tool": "browser_probe",
            "evidence_ref": "artifact://browser-probe/1",
            "confidence": 0.95,
            "facts": {"sanitization_detected": False},
            "hypothesis_ids": ["RH-example"],
        },
        {
            "id": "obs-invalid-verified",
            "target_kind": "node",
            "target_id": sink.node_id,
            "evidence_level": "verified",
            "source_agent": "audit",
            "source_tool": "read_source",
            "evidence_ref": "artifact://source/1",
            "facts": {},
        },
    ])

    assert result["accepted_observation_ids"] == ["obs-runtime-sink-1"]
    assert result["rejected_observations"][0]["observation_id"] == "obs-invalid-verified"
    assert result["previous_fingerprint"] != result["current_fingerprint"]
    assert sink.evidence["level"] == "runtime_observed"
    assert sink.attributes["sanitization_detected"] is False
    assert sink.node_id in result["graph_diff"]["changed_nodes"]
    assert graph.metadata["coverage"]["evidence_counts"]["runtime_observed"] >= 1

    weaker = graph.apply_observations([{
        "id": "obs-weaker-static-1",
        "target_kind": "node",
        "target_id": sink.node_id,
        "evidence_level": "static_observed",
        "source_agent": "audit",
        "source_tool": "read_source",
        "evidence_ref": "artifact://source/2",
        "confidence": 0.8,
        "facts": {"sanitization_detected": True},
    }])
    assert weaker["accepted_observation_ids"] == ["obs-weaker-static-1"]
    assert sink.evidence["level"] == "runtime_observed"
    assert sink.attributes["sanitization_detected"] is False


def test_graph_fingerprint_ignores_observation_run_identity_but_keeps_security_facts(tmp_path):
    surface = _build_surface(tmp_path)
    first = RuntimeSurfaceGraph.from_surface(surface)
    second = RuntimeSurfaceGraph.from_surface(surface)
    first_sink = next(node for node in first.nodes if node.node_type == "browser_sink")
    second_sink = next(node for node in second.nodes if node.node_type == "browser_sink")
    base = {
        "target_kind": "node",
        "evidence_level": "runtime_observed",
        "source_agent": "verification",
        "source_tool": "browser_probe",
        "confidence": 0.95,
        "facts": {"sanitization_detected": False},
    }
    first.apply_observations([{
        **base,
        "id": "obs-run-one",
        "target_id": first_sink.node_id,
        "evidence_ref": "artifact://run-one",
        "provenance": {"run_id": "run-one"},
    }])
    second.apply_observations([{
        **base,
        "id": "obs-run-two",
        "target_id": second_sink.node_id,
        "evidence_ref": "artifact://run-two",
        "provenance": {"run_id": "run-two"},
    }])

    assert first.content_fingerprint() == second.content_fingerprint()


def test_surface_agent_emits_graph_diff_against_previous_model(tmp_path):
    (tmp_path / "app.py").write_text(
        "system_prompt = 'Answer user input'\n"
        "def shell_tool(query):\n"
        "    return os.system(query)\n",
        encoding="utf-8",
    )
    agent = SurfaceAgent()
    first = asyncio.run(agent.run({"project_path": str(tmp_path)}))
    second = asyncio.run(agent.run({
        "project_path": str(tmp_path),
        "previous_runtime_surface_graph": first.data["runtime_surface_graph"],
    }))

    assert first.success is True
    assert second.success is True
    graph_diff = second.data["runtime_surface_graph_diff"]
    assert graph_diff["added_nodes"] == []
    assert graph_diff["removed_nodes"] == []
    assert graph_diff["changed_nodes"] == []
    assert graph_diff["added_edges"] == []
    assert graph_diff["removed_edges"] == []
    assert graph_diff["changed_edges"] == []
