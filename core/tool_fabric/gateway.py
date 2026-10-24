"""Policy, scope, timeout, and audit gateway for every Agent tool call."""

from __future__ import annotations

import asyncio
import inspect
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from ..runtime.permission_policy import PermissionPolicy
from .artifacts import ArtifactStore
from .models import (
    ToolAdapterError,
    ToolExecution,
    ToolExecutionStatus,
    ToolRequest,
    ToolResult,
    redact_mapping,
    utc_now,
)
from .registry import ToolRegistry


@dataclass
class ToolExecutionContext:
    project_root: Path
    artifact_store: ArtifactStore
    session_id: str
    task_id: str
    metadata: Dict[str, Any]


class ToolGateway:
    PATH_ARGUMENTS = {
        "path", "file_path", "directory_path", "database_path", "project_path", "cwd", "root",
    }

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        project_root: str,
        artifact_store: ArtifactStore,
        policy: Optional[PermissionPolicy] = None,
        max_inline_output_bytes: int = 64_000,
        audit_sink: Optional[Callable[[ToolExecution], Any]] = None,
    ):
        self.registry = registry
        self.project_root = Path(project_root).resolve()
        self.artifact_store = artifact_store
        self.policy = policy or PermissionPolicy(allow_network_access=False, allow_file_write=False)
        self.max_inline_output_bytes = max(1_024, int(max_inline_output_bytes))
        self.audit_sink = audit_sink
        self.executions: List[ToolExecution] = []

    async def execute(self, request: ToolRequest) -> ToolExecution:
        started = time.monotonic()
        adapter = self.registry.get(request.tool_name)
        if adapter is None:
            return await self._finish(ToolExecution(
                request_id=request.request_id,
                tool_name=request.tool_name,
                status=ToolExecutionStatus.BLOCKED,
                allowed=False,
                policy_reason="tool is not registered",
                error=f"Unknown tool: {request.tool_name}",
            ), started)

        scope_error = self._validate_scope(request.arguments)
        if scope_error:
            return await self._finish(ToolExecution(
                request_id=request.request_id,
                tool_name=adapter.spec.name,
                status=ToolExecutionStatus.BLOCKED,
                allowed=False,
                policy_reason=scope_error,
                error=scope_error,
            ), started)

        fixed_endpoint = str(adapter.spec.metadata.get("network_endpoint", "") or "")
        requested_url = str(request.arguments.get("target_url", request.arguments.get("url", "")))
        target_url = fixed_endpoint or requested_url
        decision = self.policy.check(
            tool_name=adapter.spec.name,
            target_url=target_url,
            critical_action=str(request.arguments.get("critical_action", request.arguments.get("action", ""))),
            file_size_mb=float(request.arguments.get("file_size_mb", 0) or 0),
        )
        if not decision.allowed:
            return await self._finish(ToolExecution(
                request_id=request.request_id,
                tool_name=adapter.spec.name,
                status=ToolExecutionStatus.BLOCKED,
                allowed=False,
                policy_reason=decision.reason,
                metadata={"policy_applied": decision.policy_applied},
            ), started)

        execution = ToolExecution(
            request_id=request.request_id,
            tool_name=adapter.spec.name,
            status=ToolExecutionStatus.COMPLETED,
            allowed=True,
            policy_reason=decision.reason,
            metadata={
                "policy_applied": decision.policy_applied,
                "request": request.to_dict(redact=True),
                "tool_spec_version": adapter.spec.version,
                "network_endpoint": fixed_endpoint or None,
            },
        )
        context = ToolExecutionContext(
            project_root=self.project_root,
            artifact_store=self.artifact_store,
            session_id=request.session_id,
            task_id=request.task_id,
            metadata=dict(request.target_scope),
        )
        try:
            result = await asyncio.wait_for(
                adapter.execute(request, context),
                timeout=adapter.spec.timeout_seconds,
            )
            self._bind_result(execution, result)
            self._limit_inline_output(execution)
        except asyncio.TimeoutError:
            execution.status = ToolExecutionStatus.TIMED_OUT
            execution.error = f"Tool timed out after {adapter.spec.timeout_seconds:g}s"
        except ToolAdapterError as exc:
            self._bind_result(execution, exc.result)
            self._limit_inline_output(execution)
            execution.status = exc.status
            execution.error = str(exc)
        except Exception as exc:
            execution.status = ToolExecutionStatus.FAILED
            execution.error = str(exc)
        return await self._finish(execution, started)

    async def execute_for_agent(
        self,
        name: str,
        arguments: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        context = dict(context or {})
        execution = await self.execute(ToolRequest(
            tool_name=name,
            arguments=dict(arguments or {}),
            session_id=str(context.get("session_id", "local")),
            task_id=str(context.get("task_id", "local")),
            target_scope=dict(context.get("target_scope", {})),
        ))
        payload = execution.to_dict()
        if execution.status != ToolExecutionStatus.COMPLETED:
            payload["blocked"] = execution.status == ToolExecutionStatus.BLOCKED
        return payload

    async def record_duplicate(
        self,
        name: str,
        arguments: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Persist a cache hit as an auditable non-execution terminal state."""
        started = time.monotonic()
        context = dict(context or {})
        request = ToolRequest(
            tool_name=name,
            arguments=dict(arguments or {}),
            session_id=str(context.get("session_id", "local")),
            task_id=str(context.get("task_id", "local")),
            target_scope=dict(context.get("target_scope", {})),
        )
        execution = ToolExecution(
            request_id=request.request_id,
            tool_name=name,
            status=ToolExecutionStatus.DUPLICATE,
            allowed=True,
            policy_reason="identical request already completed in this Agent task",
            output={
                "duplicate": True,
                "cached": True,
                "message": "Use the previous tool result and continue or finalize.",
            },
            metadata={"request": request.to_dict(redact=True)},
        )
        return (await self._finish(execution, started)).to_dict()

    def _validate_scope(self, arguments: Dict[str, Any]) -> Optional[str]:
        for key, raw_value in arguments.items():
            if key not in self.PATH_ARGUMENTS or raw_value in (None, ""):
                continue
            value = Path(str(raw_value))
            target = value.resolve() if value.is_absolute() else (self.project_root / value).resolve()
            try:
                target.relative_to(self.project_root)
            except ValueError:
                return f"{key} escapes project root"
        for key in ("target_url", "url"):
            raw_url = str(arguments.get(key, ""))
            if raw_url and urlparse(raw_url).scheme not in {"http", "https"}:
                return f"{key} uses an unsupported URL scheme"
        return None

    @staticmethod
    def _bind_result(execution: ToolExecution, result: ToolResult) -> None:
        execution.output = redact_mapping(dict(result.output))
        execution.artifacts = list(result.artifacts)
        execution.signals = list(result.signals)
        for signal in execution.signals:
            signal.tool_execution_id = execution.execution_id
            if not signal.artifact_refs:
                signal.artifact_refs = [item.artifact_id for item in execution.artifacts]

    def _limit_inline_output(self, execution: ToolExecution) -> None:
        serialized = json.dumps(execution.output, ensure_ascii=False, default=str).encode("utf-8")
        if len(serialized) <= self.max_inline_output_bytes:
            return
        artifact = self.artifact_store.put_bytes(
            serialized,
            producer=execution.tool_name,
            artifact_type="tool_output",
            file_name="tool-output.json",
            media_type="application/json",
            metadata={"execution_id": execution.execution_id, "truncated_inline": True},
        )
        execution.artifacts.append(artifact)
        execution.output = {
            "truncated": True,
            "original_size_bytes": len(serialized),
            "artifact_ref": artifact.artifact_id,
        }

    async def _finish(self, execution: ToolExecution, started: float) -> ToolExecution:
        execution.ended_at = utc_now()
        execution.duration_ms = int((time.monotonic() - started) * 1_000)
        self.executions.append(execution)
        if self.audit_sink:
            result = self.audit_sink(execution)
            if inspect.isawaitable(result):
                await result
        return execution
