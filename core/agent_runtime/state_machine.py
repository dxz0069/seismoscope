"""Strict, serializable state machine for one agent task."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentRuntimeState(str, Enum):
    CREATED = "created"
    PLANNED = "planned"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    WAITING_TOOL = "waiting_tool"
    WAITING_HANDOFF = "waiting_handoff"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"
    PAUSED = "paused"


class InvalidTransitionError(RuntimeError):
    """Raised when a task attempts a transition outside its contract."""

    def __init__(self, current: AgentRuntimeState, target: AgentRuntimeState):
        super().__init__(f"Illegal agent task transition: {current.value} -> {target.value}")
        self.current = current
        self.target = target


@dataclass
class StateTransition:
    from_state: AgentRuntimeState
    to_state: AgentRuntimeState
    reason: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "reason": self.reason,
            "data": self.data,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StateTransition":
        return cls(
            from_state=AgentRuntimeState(data["from_state"]),
            to_state=AgentRuntimeState(data["to_state"]),
            reason=str(data.get("reason", "")),
            data=dict(data.get("data", {})),
            timestamp=str(data.get("timestamp", _now())),
        )


TransitionSink = Callable[[StateTransition], None]


class TaskStateMachine:
    """Explicit transition table shared by all agent task types."""

    TRANSITIONS = {
        AgentRuntimeState.CREATED: {
            AgentRuntimeState.PLANNED,
            AgentRuntimeState.PAUSED,
            AgentRuntimeState.STOPPED,
        },
        AgentRuntimeState.PLANNED: {
            AgentRuntimeState.DISPATCHED,
            AgentRuntimeState.PAUSED,
            AgentRuntimeState.STOPPED,
        },
        AgentRuntimeState.DISPATCHED: {
            AgentRuntimeState.RUNNING,
            AgentRuntimeState.PAUSED,
            AgentRuntimeState.STOPPED,
        },
        AgentRuntimeState.RUNNING: {
            AgentRuntimeState.WAITING_TOOL,
            AgentRuntimeState.WAITING_HANDOFF,
            AgentRuntimeState.VERIFYING,
            AgentRuntimeState.FAILED,
            AgentRuntimeState.PAUSED,
            AgentRuntimeState.STOPPED,
        },
        AgentRuntimeState.WAITING_TOOL: {
            AgentRuntimeState.RUNNING,
            AgentRuntimeState.FAILED,
            AgentRuntimeState.PAUSED,
            AgentRuntimeState.STOPPED,
        },
        AgentRuntimeState.WAITING_HANDOFF: {
            AgentRuntimeState.RUNNING,
            AgentRuntimeState.VERIFYING,
            AgentRuntimeState.FAILED,
            AgentRuntimeState.PAUSED,
            AgentRuntimeState.STOPPED,
        },
        AgentRuntimeState.VERIFYING: {
            AgentRuntimeState.COMPLETED,
            AgentRuntimeState.RUNNING,
            AgentRuntimeState.WAITING_HANDOFF,
            AgentRuntimeState.FAILED,
            AgentRuntimeState.PAUSED,
            AgentRuntimeState.STOPPED,
        },
        AgentRuntimeState.FAILED: {
            AgentRuntimeState.DISPATCHED,
            AgentRuntimeState.PAUSED,
            AgentRuntimeState.STOPPED,
        },
        AgentRuntimeState.PAUSED: {
            AgentRuntimeState.RUNNING,
            AgentRuntimeState.DISPATCHED,
            AgentRuntimeState.WAITING_TOOL,
            AgentRuntimeState.WAITING_HANDOFF,
            AgentRuntimeState.VERIFYING,
            AgentRuntimeState.STOPPED,
        },
        AgentRuntimeState.COMPLETED: set(),
        AgentRuntimeState.STOPPED: set(),
    }

    def __init__(
        self,
        state: AgentRuntimeState = AgentRuntimeState.CREATED,
        *,
        history: Optional[Iterable[StateTransition]] = None,
        sink: Optional[TransitionSink] = None,
    ):
        self.state = state
        self.history = list(history or [])
        self.sink = sink

    @property
    def is_terminal(self) -> bool:
        return self.state in {
            AgentRuntimeState.COMPLETED,
            AgentRuntimeState.FAILED,
            AgentRuntimeState.STOPPED,
        }

    def can_transition(self, target: AgentRuntimeState) -> bool:
        return target == self.state or target in self.TRANSITIONS[self.state]

    def transition(
        self,
        target: AgentRuntimeState,
        *,
        reason: str = "",
        data: Optional[Dict[str, Any]] = None,
    ) -> StateTransition:
        if isinstance(target, str):
            target = AgentRuntimeState(target)
        if target != self.state and not self.can_transition(target):
            raise InvalidTransitionError(self.state, target)
        transition = StateTransition(
            from_state=self.state,
            to_state=target,
            reason=reason,
            data=dict(data or {}),
        )
        self.state = target
        self.history.append(transition)
        if self.sink:
            self.sink(transition)
        return transition

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "history": [item.to_dict() for item in self.history],
        }

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
        *,
        sink: Optional[TransitionSink] = None,
    ) -> "TaskStateMachine":
        return cls(
            state=AgentRuntimeState(data.get("state", AgentRuntimeState.CREATED.value)),
            history=[StateTransition.from_dict(item) for item in data.get("history", [])],
            sink=sink,
        )
