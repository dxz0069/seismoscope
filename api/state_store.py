"""Durable storage for the REST API's project and audit state."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


class ApiStateStore:
    """A small SQLite repository that keeps API payloads durable across restarts."""

    def __init__(self, database_path: str | Path):
        self.path = Path(database_path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(str(self.path), check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_tasks (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audit_tasks_project_id
                    ON audit_tasks(project_id);

                CREATE TABLE IF NOT EXISTS findings (
                    task_id TEXT NOT NULL,
                    id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (task_id, id)
                );

                CREATE INDEX IF NOT EXISTS idx_findings_task_id
                    ON findings(task_id);

                CREATE TABLE IF NOT EXISTS remediations (
                    task_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (task_id, finding_id)
                );

                CREATE INDEX IF NOT EXISTS idx_remediations_task_id
                    ON remediations(task_id);

                CREATE TABLE IF NOT EXISTS model_configs (
                    id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _as_payload(value: Any) -> tuple[dict[str, Any], str]:
        if hasattr(value, "model_dump"):
            payload = value.model_dump(mode="json")
        elif isinstance(value, Mapping):
            payload = dict(value)
        else:
            raise TypeError("State values must be mappings or Pydantic models")
        return payload, json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _updated_at(payload: Mapping[str, Any]) -> str:
        for key in ("updated_at", "completed_at", "started_at", "created_at"):
            value = payload.get(key)
            if value:
                return str(value)
        return ""

    @staticmethod
    def _decode(payload: str) -> dict[str, Any]:
        decoded = json.loads(payload)
        if not isinstance(decoded, dict):
            raise ValueError("Persisted API payload must be a JSON object")
        return decoded

    def save_project(self, project: Any) -> None:
        payload, serialized = self._as_payload(project)
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO projects(id, payload, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                (payload["id"], serialized, self._updated_at(payload)),
            )

    def delete_project(self, project_id: str) -> None:
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM projects WHERE id = ?", (project_id,))

    def save_audit_task(self, task: Any) -> None:
        payload, serialized = self._as_payload(task)
        with self._lock, self._connection:
            self._upsert_task(payload, serialized)

    def save_model_config(self, config: Any) -> None:
        """Persist an API-local model configuration, including its credential."""
        payload, serialized = self._as_payload(config)
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO model_configs(id, payload, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                (payload["id"], serialized, self._updated_at(payload)),
            )

    def delete_model_config(self, config_id: str) -> None:
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM model_configs WHERE id = ?", (config_id,))

    def save_finding(self, finding: Any) -> None:
        payload, serialized = self._as_payload(finding)
        with self._lock, self._connection:
            self._upsert_finding(payload, serialized)

    def replace_task_results(
        self,
        task: Any,
        findings: Iterable[Any],
        remediations: Iterable[Any],
    ) -> None:
        task_payload, task_serialized = self._as_payload(task)
        finding_rows = [self._as_payload(item) for item in findings]
        remediation_rows = [self._as_payload(item) for item in remediations]
        task_id = task_payload["id"]

        with self._lock, self._connection:
            self._upsert_task(task_payload, task_serialized)
            self._connection.execute("DELETE FROM findings WHERE task_id = ?", (task_id,))
            self._connection.execute("DELETE FROM remediations WHERE task_id = ?", (task_id,))
            for payload, serialized in finding_rows:
                self._upsert_finding(payload, serialized)
            for payload, serialized in remediation_rows:
                self._upsert_remediation(task_id, payload, serialized)

    def load_state(self) -> dict[str, list[dict[str, Any]]]:
        with self._lock:
            projects = self._connection.execute(
                "SELECT payload FROM projects ORDER BY updated_at, id"
            ).fetchall()
            tasks = self._connection.execute(
                "SELECT payload FROM audit_tasks ORDER BY updated_at, id"
            ).fetchall()
            findings = self._connection.execute(
                "SELECT task_id, payload FROM findings ORDER BY task_id, updated_at, id"
            ).fetchall()
            remediations = self._connection.execute(
                "SELECT task_id, payload FROM remediations "
                "ORDER BY task_id, updated_at, finding_id"
            ).fetchall()
            model_configs = self._connection.execute(
                "SELECT payload FROM model_configs ORDER BY updated_at, id"
            ).fetchall()

        return {
            "projects": [self._decode(row["payload"]) for row in projects],
            "audit_tasks": [self._decode(row["payload"]) for row in tasks],
            "findings": [
                {"task_id": row["task_id"], "payload": self._decode(row["payload"])}
                for row in findings
            ],
            "remediations": [
                {"task_id": row["task_id"], "payload": self._decode(row["payload"])}
                for row in remediations
            ],
            "model_configs": [self._decode(row["payload"]) for row in model_configs],
        }

    def clear(self) -> None:
        """Clear persisted records while retaining the database and schema."""
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM remediations")
            self._connection.execute("DELETE FROM findings")
            self._connection.execute("DELETE FROM audit_tasks")
            self._connection.execute("DELETE FROM projects")
            self._connection.execute("DELETE FROM model_configs")

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _upsert_task(self, payload: Mapping[str, Any], serialized: str) -> None:
        self._connection.execute(
            """
            INSERT INTO audit_tasks(id, project_id, payload, updated_at) VALUES (?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                project_id = excluded.project_id,
                payload = excluded.payload,
                updated_at = excluded.updated_at
            """,
            (
                payload["id"],
                payload["project_id"],
                serialized,
                self._updated_at(payload),
            ),
        )

    def _upsert_finding(self, payload: Mapping[str, Any], serialized: str) -> None:
        self._connection.execute(
            """
            INSERT INTO findings(task_id, id, payload, updated_at) VALUES (?, ?, ?, ?)
            ON CONFLICT(task_id, id) DO UPDATE SET
                payload = excluded.payload,
                updated_at = excluded.updated_at
            """,
            (
                payload["task_id"],
                payload["id"],
                serialized,
                self._updated_at(payload),
            ),
        )

    def _upsert_remediation(
        self,
        task_id: str,
        payload: Mapping[str, Any],
        serialized: str,
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO remediations(task_id, finding_id, payload, updated_at) VALUES (?, ?, ?, ?)
            ON CONFLICT(task_id, finding_id) DO UPDATE SET
                payload = excluded.payload,
                updated_at = excluded.updated_at
            """,
            (
                task_id,
                payload["finding_id"],
                serialized,
                self._updated_at(payload),
            ),
        )
