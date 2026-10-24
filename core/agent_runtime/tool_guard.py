"""Permission and audit wrapper for high-privilege agent tool calls."""

from __future__ import annotations

import inspect
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..runtime.permission_policy import PermissionPolicy


@dataclass
class ToolExecutionRecord:
    tool_name: str
    arguments: Dict[str, Any]
    allowed: bool
    policy_reason: str
    status: str = "blocked"
    output: Any = None
    error: Optional[str] = None
    duration_ms: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "allowed": self.allowed,
            "policy_reason": self.policy_reason,
            "status": self.status,
            "output": self.output,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
        }


class PermissionedToolExecutor:
    """Run tools only after policy approval and emit an audit record per call."""

    def __init__(
        self,
        executor: Callable[..., Any],
        *,
        policy: PermissionPolicy,
        audit_sink: Optional[Callable[[ToolExecutionRecord], Any]] = None,
        confirmation_callback: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
        require_confirmation_for: Optional[List[str]] = None,
    ):
        self.executor = executor
        self.policy = policy
        self.audit_sink = audit_sink
        self.confirmation_callback = confirmation_callback
        self.require_confirmation_for = {item.lower() for item in (require_confirmation_for or [])}
        self.records: List[ToolExecutionRecord] = []

    async def execute(self, *, name: str, arguments: Dict[str, Any], context: Optional[Dict[str, Any]] = None):
        del context
        arguments = dict(arguments or {})
        check = self.policy.check(
            tool_name=name,
            target_url=str(arguments.get("target_url", arguments.get("url", ""))),
            critical_action=str(arguments.get("critical_action", arguments.get("action", ""))),
            file_size_mb=float(arguments.get("file_size_mb", 0) or 0),
        )
        record = ToolExecutionRecord(
            tool_name=name,
            arguments=arguments,
            allowed=check.allowed,
            policy_reason=check.reason,
            metadata={"policy_applied": check.policy_applied},
        )
        started = time.monotonic()
        try:
            if not check.allowed:
                record.output = {"blocked": True, "reason": check.reason}
                return record.output
            if name.lower() in self.require_confirmation_for:
                if not self.confirmation_callback:
                    record.allowed = False
                    record.output = {"blocked": True, "reason": "human confirmation required"}
                    return record.output
                approved = self.confirmation_callback(name, arguments)
                approved = await approved if inspect.isawaitable(approved) else approved
                if not approved:
                    record.allowed = False
                    record.output = {"blocked": True, "reason": "human confirmation denied"}
                    return record.output

            result = self.executor(name, arguments)
            result = await result if inspect.isawaitable(result) else result
            record.status = "completed"
            record.output = result
            return result
        except Exception as exc:
            record.status = "failed"
            record.error = str(exc)
            raise
        finally:
            record.duration_ms = int((time.monotonic() - started) * 1000)
            self.records.append(record)
            if self.audit_sink:
                result = self.audit_sink(record)
                if inspect.isawaitable(result):
                    await result
