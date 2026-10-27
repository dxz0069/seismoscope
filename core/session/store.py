"""JSONL session persistence for local CLI and Skill workflows."""

import json
from datetime import date, datetime
from enum import Enum
from pathlib import Path

from .models import Checkpoint, RunSession


def _json_default(value):
    """Keep snapshots durable when an agent returns domain objects."""
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    return repr(value)


class SessionStore:
    """Durable local session snapshots; intentionally no database dependency."""

    def __init__(self, root: str):
        self.root = Path(root)

    def save(self, session: RunSession) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.path_for(session.session_id)
        temporary = path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(
                json.dumps(session.to_dict(), ensure_ascii=False, default=_json_default) + "\n"
            )
            handle.flush()
        temporary.replace(path)
        return path

    def path_for(self, session_id: str) -> Path:
        """Return the canonical local path without reading or creating a snapshot."""
        return self.root / f"{session_id}.jsonl"

    def reference(self, session: RunSession) -> dict:
        """Return a stable, local-only reference suitable for Skill output."""
        path = self.path_for(session.session_id)
        return {
            "session_id": session.session_id,
            "path": str(path),
            "status": session.status.value,
        }

    def list_sessions(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(self.root.glob("run-*.jsonl"))

    def load(self, session_id_or_path: str | Path) -> RunSession:
        """Load the newest snapshot, including sessions written by legacy JSONL stores."""
        candidate = Path(session_id_or_path)
        path = candidate if candidate.suffix == ".jsonl" else self.path_for(str(candidate))
        if not path.exists():
            raise FileNotFoundError(f"Session snapshot not found: {path}")
        latest = None
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    latest = json.loads(line)
        if latest is None:
            raise ValueError(f"Session snapshot is empty: {path}")
        return RunSession.from_dict(latest)

    def latest_checkpoint(self, session_id_or_path: str | Path) -> Checkpoint | None:
        session = self.load(session_id_or_path)
        return session.checkpoints[-1] if session.checkpoints else None
