"""Stable contracts for agent-visible tools and their evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, UTC
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from ..sanitization import SENSITIVE_KEY_PARTS, redact_sensitive_text


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class ToolRiskClass(str, Enum):
    READ_ONLY = "read_only"
    SCANNER = "scanner"
    ACTIVE = "active"
    MUTATING = "mutating"


class ToolExecutionStatus(str, Enum):
    COMPLETED = "completed"
    DUPLICATE = "duplicate"
    BLOCKED = "blocked"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    version: str = "1"
    capability: str = "analysis"
    output_schema: dict[str, Any] = field(default_factory=dict)
    risk_class: ToolRiskClass = ToolRiskClass.READ_ONLY
    required_permissions: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    timeout_seconds: float = 30.0
    concurrency_safe: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "").replace("-", "").isalnum():
            raise ValueError("ToolSpec.name must be a non-empty tool identifier")
        if self.timeout_seconds <= 0:
            raise ValueError("ToolSpec.timeout_seconds must be positive")

    def to_openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.input_schema or {"type": "object", "properties": {}},
            },
        }

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["risk_class"] = self.risk_class.value
        return payload


@dataclass
class ToolRequest:
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    session_id: str = "local"
    task_id: str = "local"
    target_scope: dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: f"toolreq-{uuid4().hex}")
    created_at: str = field(default_factory=utc_now)

    def to_dict(self, *, redact: bool = False) -> dict[str, Any]:
        arguments = redact_mapping(self.arguments) if redact else dict(self.arguments)
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "task_id": self.task_id,
            "tool_name": self.tool_name,
            "arguments": arguments,
            "target_scope": dict(self.target_scope),
            "created_at": self.created_at,
        }


@dataclass
class ArtifactRef:
    artifact_id: str
    artifact_type: str
    path: str
    sha256: str
    size_bytes: int
    producer: str
    media_type: str = "application/octet-stream"
    created_at: str = field(default_factory=utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolSignal:
    kind: str
    summary: str
    tool_execution_id: str = ""
    signal_id: str = field(default_factory=lambda: f"signal-{uuid4().hex}")
    severity: str = "info"
    confidence: float = 0.5
    rule_id: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    artifact_refs: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolResult:
    output: dict[str, Any] = field(default_factory=dict)
    signals: list[ToolSignal] = field(default_factory=list)
    artifacts: list[ArtifactRef] = field(default_factory=list)


class ToolAdapterError(RuntimeError):
    """Adapter failure that preserves evidence collected before the failure."""

    def __init__(
        self,
        message: str,
        *,
        result: ToolResult | None = None,
        status: ToolExecutionStatus = ToolExecutionStatus.FAILED,
    ):
        super().__init__(message)
        self.result = result or ToolResult()
        self.status = status


@dataclass
class ToolExecution:
    request_id: str
    tool_name: str
    status: ToolExecutionStatus
    allowed: bool
    policy_reason: str
    execution_id: str = field(default_factory=lambda: f"toolexec-{uuid4().hex}")
    started_at: str = field(default_factory=utc_now)
    ended_at: str | None = None
    duration_ms: int = 0
    output: dict[str, Any] = field(default_factory=dict)
    signals: list[ToolSignal] = field(default_factory=list)
    artifacts: list[ArtifactRef] = field(default_factory=list)
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "request_id": self.request_id,
            "tool_name": self.tool_name,
            "status": self.status.value,
            "allowed": self.allowed,
            "policy_reason": self.policy_reason,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "output": self.output,
            "signals": [item.to_dict() for item in self.signals],
            "artifacts": [item.to_dict() for item in self.artifacts],
            "error": self.error,
            "metadata": self.metadata,
        }


def redact_mapping(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            sensitive_key = any(part in lowered for part in SENSITIVE_KEY_PARTS)
            should_redact = sensitive_key and isinstance(item, (str, bytes, dict, list, tuple))
            redacted[key] = "[REDACTED]" if should_redact else redact_mapping(item)
        return redacted
    if isinstance(value, list):
        return [redact_mapping(item) for item in value]
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value
