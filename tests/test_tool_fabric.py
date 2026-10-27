"""Tests for the unified Agent tool protocol and policy gateway."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from core.runtime.permission_policy import PermissionPolicy
from core.tool_fabric import (
    ArtifactStore,
    CallableToolAdapter,
    ToolExecutionStatus,
    ToolGateway,
    ToolRegistry,
    ToolRequest,
    ToolResult,
    ToolRiskClass,
    ToolSignal,
    ToolSpec,
)


def make_spec(name="read_source", *, timeout=1.0):
    return ToolSpec(
        name=name,
        description="Read bounded source evidence.",
        input_schema={
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
        capability="source.read",
        risk_class=ToolRiskClass.READ_ONLY,
        timeout_seconds=timeout,
        aliases=["read_file"] if name == "read_source" else [],
    )


def test_tool_spec_and_registry_expose_stable_llm_schema():
    registry = ToolRegistry()
    registry.register(CallableToolAdapter(make_spec(), lambda request, context: ToolResult()))

    schema = registry.openai_schemas()[0]

    assert registry.get("read_file").spec.name == "read_source"
    assert schema["function"]["name"] == "read_source"
    assert schema["function"]["parameters"]["required"] == ["file_path"]


def test_gateway_binds_signal_provenance_and_redacts_request(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    registry = ToolRegistry()

    async def execute(request, context):
        artifact = context.artifact_store.put_text(
            "evidence",
            producer="read_source",
            artifact_type="source_excerpt",
        )
        return ToolResult(
            output={"content": "bounded", "api_key": "must-not-leak"},
            signals=[ToolSignal(kind="source_evidence", summary="Source was read")],
            artifacts=[artifact],
        )

    registry.register(CallableToolAdapter(make_spec(), execute))
    gateway = ToolGateway(
        registry,
        project_root=str(project),
        artifact_store=ArtifactStore(str(tmp_path / "artifacts"), session_id="session-1"),
        policy=PermissionPolicy(allow_network_access=False, allow_file_write=False),
    )
    result = asyncio.run(gateway.execute(ToolRequest(
        tool_name="read_source",
        arguments={"file_path": "app.py", "api_key": "secret"},
        session_id="session-1",
        task_id="task-1",
    )))

    assert result.status == ToolExecutionStatus.COMPLETED
    assert result.output["api_key"] == "[REDACTED]"
    assert result.metadata["request"]["arguments"]["api_key"] == "[REDACTED]"
    assert result.signals[0].tool_execution_id == result.execution_id
    assert result.signals[0].artifact_refs == [result.artifacts[0].artifact_id]


def test_gateway_blocks_project_escape_before_adapter_execution(tmp_path):
    called = []
    registry = ToolRegistry()

    async def execute(request, context):
        called.append(True)
        return ToolResult()

    registry.register(CallableToolAdapter(make_spec(), execute))
    gateway = ToolGateway(
        registry,
        project_root=str(tmp_path),
        artifact_store=ArtifactStore(str(tmp_path / "artifacts")),
    )
    result = asyncio.run(gateway.execute(ToolRequest(
        tool_name="read_source",
        arguments={"file_path": "../outside.py"},
    )))

    assert result.status == ToolExecutionStatus.BLOCKED
    assert "escapes project root" in result.policy_reason
    assert called == []


def test_gateway_times_out_and_externalizes_large_output(tmp_path):
    registry = ToolRegistry()

    async def slow(request, context):
        await asyncio.sleep(0.03)
        return ToolResult(output={"ok": True})

    async def large(request, context):
        return ToolResult(output={"content": "x" * 4_000})

    registry.register(CallableToolAdapter(make_spec("slow", timeout=0.01), slow))
    registry.register(CallableToolAdapter(make_spec("large", timeout=1), large))
    gateway = ToolGateway(
        registry,
        project_root=str(tmp_path),
        artifact_store=ArtifactStore(str(tmp_path / "artifacts")),
        max_inline_output_bytes=1_024,
    )

    timed_out = asyncio.run(gateway.execute(ToolRequest(tool_name="slow")))
    externalized = asyncio.run(gateway.execute(ToolRequest(tool_name="large")))

    assert timed_out.status == ToolExecutionStatus.TIMED_OUT
    assert externalized.status == ToolExecutionStatus.COMPLETED
    assert externalized.output["truncated"] is True
    assert externalized.artifacts[0].sha256


def test_gateway_records_duplicate_cache_hits_as_terminal_executions(tmp_path):
    gateway = ToolGateway(
        ToolRegistry(),
        project_root=str(tmp_path),
        artifact_store=ArtifactStore(str(tmp_path / "artifacts")),
    )

    payload = asyncio.run(gateway.record_duplicate(
        "read_source", {"file_path": "app.py"}, {"task_id": "task-1"},
    ))

    assert payload["status"] == "duplicate"
    assert payload["output"]["duplicate"] is True
    assert gateway.executions[0].status == ToolExecutionStatus.DUPLICATE


def test_artifact_manifest_supports_query_and_explicit_tombstoned_cleanup(tmp_path):
    store = ArtifactStore(str(tmp_path / "artifacts"), session_id="manifest-test")
    first = store.put_text("one", producer="read_source", artifact_type="source_excerpt")
    second = store.put_json({"ok": True}, producer="semgrep", artifact_type="scanner_output")

    assert store.manifest_path.is_file()
    assert [item["artifact_id"] for item in store.list_artifacts(producer="read_source")] == [first.artifact_id]
    assert [item["artifact_id"] for item in store.list_artifacts(artifact_type="scanner_output")] == [second.artifact_id]

    future = datetime.now(UTC) + timedelta(seconds=1)
    preview = store.cleanup_expired(0, dry_run=True, now=future)
    assert set(preview["candidate_ids"]) == {first.artifact_id, second.artifact_id}
    assert Path(first.path).is_file()

    removed = store.cleanup_expired(0, dry_run=False, now=future)
    assert set(removed["deleted_ids"]) == {first.artifact_id, second.artifact_id}
    assert store.list_artifacts() == []
    assert {item["artifact_id"] for item in store.list_artifacts(include_deleted=True)} == {
        first.artifact_id,
        second.artifact_id,
    }
    records = [json.loads(line) for line in store.manifest_path.read_text(encoding="utf-8").splitlines()]
    assert [item["event"] for item in records] == ["created", "created", "deleted", "deleted"]


def test_json_artifacts_and_manifest_metadata_are_redacted_at_storage_boundary(tmp_path):
    store = ArtifactStore(str(tmp_path / "artifacts"), session_id="redaction-test")
    secret = "sk-storage-boundary-secret-123456"

    artifact = store.put_json(
        {"api_key": secret, "nested": {"password": "database-password"}},
        producer="test",
        metadata={"access_token": secret},
    )

    artifact_text = Path(artifact.path).read_text(encoding="utf-8")
    manifest_text = store.manifest_path.read_text(encoding="utf-8")
    assert secret not in artifact_text
    assert "database-password" not in artifact_text
    assert secret not in manifest_text
    assert artifact.metadata["access_token"] == "[REDACTED]"
