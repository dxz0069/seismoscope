"""Stable execution contracts for the local security harness.

These objects deliberately use standard-library dataclasses. Agents can keep
returning dictionaries internally while the harness records one predictable
session/event/checkpoint model at the boundary.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from ..sanitization import sanitize_for_persistence


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RunStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


@dataclass
class RunEvent:
    event_type: str
    phase: str
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: f"event-{uuid4().hex[:12]}")
    timestamp: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "phase": self.phase,
            "message": self.message,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RunEvent":
        timestamp = data.get("timestamp")
        return cls(
            event_type=str(data.get("event_type", "unknown")),
            phase=str(data.get("phase", "")),
            message=str(data.get("message", "")),
            data=dict(data.get("data", {})),
            event_id=str(data.get("event_id") or f"event-{uuid4().hex[:12]}"),
            timestamp=datetime.fromisoformat(timestamp) if timestamp else utc_now(),
        )


@dataclass
class Checkpoint:
    phase: str
    state: Dict[str, Any]
    checkpoint_id: str = field(default_factory=lambda: f"checkpoint-{uuid4().hex[:12]}")
    created_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "phase": self.phase,
            "state": self.state,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Checkpoint":
        created_at = data.get("created_at")
        return cls(
            phase=str(data.get("phase", "")),
            state=dict(data.get("state", {})),
            checkpoint_id=str(data.get("checkpoint_id") or f"checkpoint-{uuid4().hex[:12]}"),
            created_at=datetime.fromisoformat(created_at) if created_at else utc_now(),
        )


@dataclass
class RunSession:
    project_path: str
    trigger: str = "explicit"
    session_id: str = field(default_factory=lambda: f"run-{uuid4().hex[:16]}")
    status: RunStatus = RunStatus.CREATED
    started_at: datetime = field(default_factory=utc_now)
    finished_at: Optional[datetime] = None
    current_phase: str = "plan"
    phases_completed: List[str] = field(default_factory=list)
    events: List[RunEvent] = field(default_factory=list)
    checkpoints: List[Checkpoint] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def start(self) -> None:
        self.status = RunStatus.RUNNING

    def emit(
        self,
        event_type: str,
        phase: str,
        message: str = "",
        data: Optional[Dict[str, Any]] = None,
    ) -> RunEvent:
        self.current_phase = phase
        event = RunEvent(
            event_type=event_type,
            phase=phase,
            message=message,
            data=data or {},
        )
        self.events.append(event)
        return event

    def checkpoint(self, phase: str, state: Dict[str, Any]) -> Checkpoint:
        checkpoint = Checkpoint(phase=phase, state=sanitize_for_persistence(state))
        self.checkpoints.append(checkpoint)
        self.current_phase = phase
        return checkpoint

    def update_metadata(self, **values: Any) -> None:
        """Persist only redaction-safe session facts shared across Skill phases."""
        self.metadata.update(sanitize_for_persistence(values))

    def complete(self, status: RunStatus = RunStatus.COMPLETED) -> None:
        self.status = status
        self.finished_at = utc_now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "project_path": self.project_path,
            "trigger": self.trigger,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "current_phase": self.current_phase,
            "phases_completed": self.phases_completed,
            "events": [event.to_dict() for event in self.events],
            "checkpoints": [checkpoint.to_dict() for checkpoint in self.checkpoints],
            "metadata": sanitize_for_persistence(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RunSession":
        def parse_datetime(value: Optional[str]) -> Optional[datetime]:
            return datetime.fromisoformat(value) if value else None

        return cls(
            project_path=str(data.get("project_path", "")),
            trigger=str(data.get("trigger", "explicit")),
            session_id=str(data.get("session_id") or f"run-{uuid4().hex[:16]}"),
            status=RunStatus(data.get("status", RunStatus.CREATED.value)),
            started_at=parse_datetime(data.get("started_at")) or utc_now(),
            finished_at=parse_datetime(data.get("finished_at")),
            current_phase=str(data.get("current_phase", "plan")),
            phases_completed=list(data.get("phases_completed", [])),
            events=[RunEvent.from_dict(item) for item in data.get("events", [])],
            checkpoints=[Checkpoint.from_dict(item) for item in data.get("checkpoints", [])],
            metadata=dict(data.get("metadata", {})),
        )
