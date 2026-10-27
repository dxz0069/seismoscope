"""Atomic local persistence for immutable VRTM model snapshots."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4


class VRTMModelStore:
    def __init__(self, project_path: str, root: str | None = None):
        project = Path(project_path).resolve()
        self.root = Path(root).resolve() if root else self._default_root(project)
        self.snapshots = self.root / "snapshots"
        self.latest_path = self.root / "latest.json"

    @staticmethod
    def _default_root(project: Path) -> Path:
        """Keep runtime snapshots outside read-only source mounts when configured."""
        state_root = os.getenv("VIBE_SEC_VRTM_STATE_DIR", "").strip()
        if not state_root:
            return project / ".vibe-sec" / "vrtm"
        project_id = hashlib.sha256(str(project).encode("utf-8")).hexdigest()[:24]
        return Path(state_root).resolve() / project_id

    def save(self, result: dict[str, Any]) -> dict[str, Any]:
        fingerprint = str(result.get("model_fingerprint", ""))
        if not fingerprint:
            raise ValueError("VRTM result has no model fingerprint")
        self.snapshots.mkdir(parents=True, exist_ok=True)
        snapshot_id = fingerprint[:16]
        snapshot_path = self.snapshots / f"{snapshot_id}.json"
        payload = dict(result)
        payload["snapshot"] = {
            "id": snapshot_id,
            "fingerprint": fingerprint,
            "graph_fingerprint": result.get("graph_fingerprint"),
            "model_fingerprint": fingerprint,
            "created_at": datetime.now(UTC).isoformat(),
            "path": str(snapshot_path),
        }
        if not snapshot_path.exists():
            self._atomic_json(snapshot_path, payload)
        else:
            existing = self._read(snapshot_path)
            payload["snapshot"] = dict(existing.get("snapshot", payload["snapshot"]))
        self._atomic_json(self.latest_path, payload)
        return dict(payload["snapshot"])

    def load_latest(self) -> dict[str, Any] | None:
        if not self.latest_path.is_file():
            return None
        return self._read(self.latest_path)

    def load(self, snapshot_id: str) -> dict[str, Any]:
        if not snapshot_id or any(item in snapshot_id for item in ("/", "\\", "..")):
            raise ValueError("invalid VRTM snapshot id")
        path = self.snapshots / f"{snapshot_id}.json"
        if not path.is_file():
            raise FileNotFoundError(f"VRTM snapshot not found: {snapshot_id}")
        return self._read(path)

    def list_snapshots(self) -> list[dict[str, Any]]:
        if not self.snapshots.is_dir():
            return []
        values = []
        for path in self.snapshots.glob("*.json"):
            try:
                snapshot = self._read(path).get("snapshot", {})
            except (OSError, ValueError):
                continue
            if snapshot:
                values.append(dict(snapshot))
        return sorted(values, key=lambda item: str(item.get("created_at", "")), reverse=True)

    @staticmethod
    def _read(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid VRTM snapshot {path}: {exc}") from exc
        if not isinstance(value, dict) or value.get("schema") != "vibe-sec.vrtm.result.v1":
            raise ValueError(f"Unsupported VRTM snapshot schema: {path}")
        return value

    @staticmethod
    def _atomic_json(path: Path, value: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + f".{os.getpid()}.{uuid4().hex}.tmp")
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        os.replace(temporary, path)
