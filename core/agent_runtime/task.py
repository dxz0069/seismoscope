"""Serializable task contract passed through the agent runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, UTC
from typing import Any, Dict, List, Optional
from uuid import uuid4

from ..agents.base import TaskHandoff
from ..sanitization import sanitize_for_persistence
from .state_machine import AgentRuntimeState, StateTransition, TaskStateMachine


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class AgentTask:
    task_id: str = field(default_factory=lambda: f"task-{uuid4().hex[:16]}")
    agent_name: str = "agent"
    parent_task_id: str | None = None
    phase: str = ""
    input_payload: dict[str, Any] = field(default_factory=dict)
    attempt: int = 0
    max_attempts: int = 3
    status: AgentRuntimeState = AgentRuntimeState.CREATED
    handoff: TaskHandoff | None = None
    completion_contract: dict[str, Any] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)
    next_action: str = ""
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    turn_count: int = 0
    total_tokens: int = 0
    last_error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    state_history: list[dict[str, Any]] = field(default_factory=list)

    def state_machine(self, sink=None) -> TaskStateMachine:
        return TaskStateMachine(
            state=self.status,
            history=[StateTransition.from_dict(item) for item in self.state_history],
            sink=sink,
        )

    def sync_state(self, machine: TaskStateMachine) -> None:
        self.status = machine.state
        self.state_history = [item.to_dict() for item in machine.history]
        self.updated_at = _utc_now()

    def is_terminal(self) -> bool:
        return self.status in {
            AgentRuntimeState.COMPLETED,
            AgentRuntimeState.FAILED,
            AgentRuntimeState.STOPPED,
        }

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_persistence({
            "task_id": self.task_id,
            "agent_name": self.agent_name,
            "parent_task_id": self.parent_task_id,
            "phase": self.phase,
            "input_payload": self.input_payload,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "status": self.status.value,
            "handoff": self.handoff.to_dict() if self.handoff else None,
            "completion_contract": self.completion_contract,
            "evidence_refs": self.evidence_refs,
            "next_action": self.next_action,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "turn_count": self.turn_count,
            "total_tokens": self.total_tokens,
            "last_error": self.last_error,
            "metadata": self.metadata,
            "state_history": self.state_history,
        })

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentTask:
        handoff = data.get("handoff")
        return cls(
            task_id=str(data.get("task_id") or f"task-{uuid4().hex[:16]}"),
            agent_name=str(data.get("agent_name", "agent")),
            parent_task_id=data.get("parent_task_id"),
            phase=str(data.get("phase", "")),
            input_payload=dict(data.get("input_payload", {})),
            attempt=int(data.get("attempt", 0)),
            max_attempts=max(1, int(data.get("max_attempts", 3))),
            status=AgentRuntimeState(data.get("status", AgentRuntimeState.CREATED.value)),
            handoff=TaskHandoff.from_dict(handoff) if handoff else None,
            completion_contract=dict(data.get("completion_contract", {})),
            evidence_refs=list(data.get("evidence_refs", [])),
            next_action=str(data.get("next_action", "")),
            created_at=str(data.get("created_at", _utc_now())),
            updated_at=str(data.get("updated_at", _utc_now())),
            turn_count=int(data.get("turn_count", 0)),
            total_tokens=int(data.get("total_tokens", 0)),
            last_error=data.get("last_error"),
            metadata=dict(data.get("metadata", {})),
            state_history=list(data.get("state_history", [])),
        )
