"""Local, signed confirmation records for consequential remediation changes."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

APPROVAL_SCHEMA = "vibe-sec.remediation-approval.v1"


def issue_remediation_approval(
    project_path: str,
    *,
    session_id: str,
    package_id: str,
    reason: str,
    approved_by: str = "local_operator",
    output_path: str | None = None,
    ttl_minutes: int = 480,
    state_root: str | None = None,
) -> dict[str, Any]:
    """Issue a project/session/package-bound local operator confirmation."""
    project = Path(project_path).resolve()
    if not project.is_dir():
        raise ValueError(f"project_path must be an existing directory: {project_path}")
    if not session_id or not package_id:
        raise ValueError("session_id and package_id are required for remediation approval")
    if not str(reason).strip():
        raise ValueError("approval reason is required")
    if not 1 <= int(ttl_minutes) <= 24 * 60:
        raise ValueError("ttl_minutes must be between 1 and 1440")

    root = _state_root(state_root)
    root.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    approval_id = f"approval-{secrets.token_hex(12)}"
    payload: dict[str, Any] = {
        "schema": APPROVAL_SCHEMA,
        "approval_id": approval_id,
        "project_root": str(project),
        "session_id": str(session_id),
        "package_id": str(package_id),
        "approved_by": str(approved_by).strip() or "local_operator",
        "reason": str(reason).strip(),
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=int(ttl_minutes))).isoformat(),
        "nonce": secrets.token_hex(16),
    }
    payload["signature"] = _sign(payload, _load_or_create_key(root))
    target = (
        Path(output_path).resolve()
        if output_path
        else root / "remediation-approvals" / f"{approval_id}.json"
    )
    _require_outside_project(target, project)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + f".{secrets.token_hex(4)}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, target)
    return {
        "schema": APPROVAL_SCHEMA,
        "approval_id": approval_id,
        "path": str(target),
        "project_root": str(project),
        "session_id": str(session_id),
        "package_id": str(package_id),
        "approved_by": payload["approved_by"],
        "expires_at": payload["expires_at"],
    }


def load_remediation_approval(
    approval_path: str,
    project_path: str,
    *,
    session_id: str,
    package_id: str,
    state_root: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate a confirmation without exposing the signature to the session."""
    project = Path(project_path).resolve()
    source = Path(approval_path).resolve()
    _require_outside_project(source, project)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid remediation approval: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != APPROVAL_SCHEMA:
        raise ValueError("Unsupported remediation approval schema")
    signature = str(payload.get("signature", ""))
    if not signature or not hmac.compare_digest(
        signature, _sign(payload, _load_or_create_key(_state_root(state_root), create=False))
    ):
        raise ValueError("Remediation approval signature is invalid")
    if Path(str(payload.get("project_root", ""))).resolve() != project:
        raise ValueError("Remediation approval is bound to a different project")
    if str(payload.get("session_id", "")) != str(session_id):
        raise ValueError("Remediation approval is bound to a different session")
    if str(payload.get("package_id", "")) != str(package_id):
        raise ValueError("Remediation approval is bound to a different package")
    try:
        expires_at = datetime.fromisoformat(str(payload.get("expires_at", "")))
    except ValueError as exc:
        raise ValueError("Remediation approval expiry is invalid") from exc
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if (now or datetime.now(UTC)) >= expires_at:
        raise ValueError("Remediation approval has expired")
    return {
        "approval_id": str(payload.get("approval_id", "")),
        "package_id": str(package_id),
        "approved_by": str(payload.get("approved_by", "local_operator")),
        "issued_at": str(payload.get("issued_at", "")),
        "expires_at": expires_at.isoformat(),
        "source": str(source),
        "trusted": True,
    }


def _state_root(value: str | None) -> Path:
    if value:
        return Path(value).resolve()
    configured = os.getenv("VIBE_SEC_STATE_HOME")
    return Path(configured).resolve() if configured else Path.home() / ".vibe-sec"


def _load_or_create_key(root: Path, *, create: bool = True) -> bytes:
    key_path = root / "remediation-approval.key"
    if not key_path.exists():
        if not create:
            raise ValueError("Remediation approval key is unavailable")
        root.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(secrets.token_bytes(32))
        try:
            key_path.chmod(0o600)
        except OSError:
            pass
    key = key_path.read_bytes()
    if len(key) < 32:
        raise ValueError("Remediation approval key is invalid")
    return key


def _sign(payload: dict[str, Any], key: bytes) -> str:
    unsigned = {name: value for name, value in payload.items() if name != "signature"}
    data = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _require_outside_project(path: Path, project: Path) -> None:
    try:
        path.relative_to(project)
    except ValueError:
        return
    raise ValueError("Remediation approval must be stored outside the audited project")
