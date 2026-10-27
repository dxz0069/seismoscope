"""Local immutable artifact storage for tool output and verification evidence."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..sanitization import sanitize_for_persistence
from .models import ArtifactRef


class ArtifactStore:
    def __init__(self, root: str, *, session_id: str = "local"):
        self.root = Path(root).resolve()
        self.session_id = _safe_segment(session_id)
        self.session_root = (self.root / self.session_id).resolve()
        self.session_root.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.session_root / "manifest.jsonl"

    def put_text(
        self,
        content: str,
        *,
        producer: str,
        artifact_type: str = "tool_output",
        file_name: str | None = None,
        media_type: str = "text/plain",
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRef:
        return self.put_bytes(
            content.encode("utf-8", errors="replace"),
            producer=producer,
            artifact_type=artifact_type,
            file_name=file_name,
            media_type=media_type,
            metadata=metadata,
        )

    def put_json(
        self,
        payload: Any,
        *,
        producer: str,
        artifact_type: str = "tool_output",
        file_name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRef:
        content = json.dumps(
            sanitize_for_persistence(payload), ensure_ascii=False, indent=2, default=str,
        )
        return self.put_text(
            content,
            producer=producer,
            artifact_type=artifact_type,
            file_name=file_name or "output.json",
            media_type="application/json",
            metadata=metadata,
        )

    def put_bytes(
        self,
        content: bytes,
        *,
        producer: str,
        artifact_type: str,
        file_name: str | None = None,
        media_type: str = "application/octet-stream",
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRef:
        artifact_id = f"artifact-{uuid4().hex}"
        suffix = Path(file_name or "output.bin").suffix or ".bin"
        target = (self.session_root / f"{artifact_id}{suffix}").resolve()
        target.relative_to(self.session_root)
        target.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        artifact = ArtifactRef(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            path=str(target),
            sha256=digest,
            size_bytes=len(content),
            producer=producer,
            media_type=media_type,
            metadata=dict(sanitize_for_persistence(metadata or {})),
        )
        self._append_manifest({"event": "created", "artifact": artifact.to_dict()})
        return artifact

    def list_artifacts(
        self,
        *,
        artifact_type: str | None = None,
        producer: str | None = None,
        include_deleted: bool = False,
    ) -> list[dict[str, Any]]:
        active: dict[str, dict[str, Any]] = {}
        deleted: dict[str, dict[str, Any]] = {}
        for record in self._manifest_records():
            if record.get("event") == "created" and isinstance(record.get("artifact"), dict):
                artifact = dict(record["artifact"])
                active[str(artifact.get("artifact_id", ""))] = artifact
            elif record.get("event") == "deleted":
                artifact_id = str(record.get("artifact_id", ""))
                artifact = active.pop(artifact_id, None)
                if artifact:
                    deleted[artifact_id] = {
                        **artifact,
                        "deleted_at": record.get("deleted_at"),
                        "deletion_reason": record.get("reason"),
                    }
        values = [*active.values(), *(deleted.values() if include_deleted else [])]
        if artifact_type:
            values = [item for item in values if item.get("artifact_type") == artifact_type]
        if producer:
            values = [item for item in values if item.get("producer") == producer]
        return sorted(values, key=lambda item: (str(item.get("created_at", "")), str(item.get("artifact_id", ""))))

    def cleanup_expired(
        self,
        max_age_days: float,
        *,
        dry_run: bool = True,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if float(max_age_days) < 0:
            raise ValueError("max_age_days must be non-negative")
        cutoff = (now or datetime.now(UTC)) - timedelta(days=float(max_age_days))
        candidates = []
        for artifact in self.list_artifacts():
            try:
                created_at = datetime.fromisoformat(str(artifact.get("created_at", "")))
            except ValueError:
                continue
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            if created_at <= cutoff:
                candidates.append(artifact)
        deleted = []
        if not dry_run:
            for artifact in candidates:
                target = Path(str(artifact.get("path", ""))).resolve()
                try:
                    target.relative_to(self.session_root)
                except ValueError:
                    continue
                if target.is_file():
                    target.unlink()
                artifact_id = str(artifact.get("artifact_id", ""))
                self._append_manifest({
                    "event": "deleted",
                    "artifact_id": artifact_id,
                    "deleted_at": datetime.now(UTC).isoformat(),
                    "reason": f"retention exceeded {max_age_days:g} days",
                })
                deleted.append(artifact_id)
        return {
            "dry_run": dry_run,
            "max_age_days": float(max_age_days),
            "candidate_ids": [str(item.get("artifact_id", "")) for item in candidates],
            "deleted_ids": deleted,
        }

    def _manifest_records(self) -> list[dict[str, Any]]:
        if not self.manifest_path.is_file():
            return []
        records = []
        with self.manifest_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    records.append(value)
        return records

    def _append_manifest(self, record: dict[str, Any]) -> None:
        with self.manifest_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(
                sanitize_for_persistence(record), ensure_ascii=False, default=str,
            ) + "\n")


def _safe_segment(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "local")).strip(".-")
    return cleaned or "local"
