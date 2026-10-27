"""Issue and validate short-lived, project-bound verification authorizations."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

AUTHORIZATION_SCHEMA = "vibe-sec.verification-authorization.v1"


def issue_verification_authorization(
    project_path: str,
    *,
    output_path: str | None = None,
    ttl_minutes: int = 15,
    allow_service_start: bool = False,
    allow_network: bool = False,
    target_scope: list[str] | None = None,
    max_duration_seconds: int = 60,
    max_attempts: int = 3,
    max_requests: int = 100,
    state_root: str | None = None,
) -> dict[str, Any]:
    project = Path(project_path).resolve()
    if not project.is_dir():
        raise ValueError(f"project_path must be an existing directory: {project_path}")
    if not 1 <= int(ttl_minutes) <= 24 * 60:
        raise ValueError("ttl_minutes must be between 1 and 1440")
    root = _state_root(state_root)
    root.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    authorization_id = f"auth-{secrets.token_hex(12)}"
    payload: dict[str, Any] = {
        "schema": AUTHORIZATION_SCHEMA,
        "authorization_id": authorization_id,
        "project_root": str(project),
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=int(ttl_minutes))).isoformat(),
        "nonce": secrets.token_hex(16),
        "policy": {
            "allow_poc_execution": True,
            "non_production": True,
            "allow_service_start": bool(allow_service_start),
            "allow_network": bool(allow_network),
            "allow_destructive_actions": False,
            "target_scope": list(target_scope or ["local-container"]),
            "max_duration_seconds": int(max_duration_seconds),
            "max_attempts": int(max_attempts),
            "max_requests": int(max_requests),
        },
    }
    payload["signature"] = _sign(payload, _load_or_create_key(root))
    target = Path(output_path).resolve() if output_path else root / "authorizations" / f"{authorization_id}.json"
    _require_outside_project(target, project)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + f".{secrets.token_hex(4)}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, target)
    return {
        "schema": AUTHORIZATION_SCHEMA,
        "authorization_id": authorization_id,
        "path": str(target),
        "project_root": str(project),
        "expires_at": payload["expires_at"],
        "policy": dict(payload["policy"]),
    }


def load_verification_authorization(
    authorization_path: str,
    project_path: str,
    *,
    state_root: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    project = Path(project_path).resolve()
    source = Path(authorization_path).resolve()
    _require_outside_project(source, project)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid verification authorization: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != AUTHORIZATION_SCHEMA:
        raise ValueError("Unsupported verification authorization schema")
    signature = str(payload.get("signature", ""))
    if not signature or not hmac.compare_digest(
        signature,
        _sign(payload, _load_or_create_key(_state_root(state_root), create=False)),
    ):
        raise ValueError("Verification authorization signature is invalid")
    if Path(str(payload.get("project_root", ""))).resolve() != project:
        raise ValueError("Verification authorization is bound to a different project")
    try:
        expires_at = datetime.fromisoformat(str(payload.get("expires_at", "")))
    except ValueError as exc:
        raise ValueError("Verification authorization expiry is invalid") from exc
    current = now or datetime.now(UTC)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if current >= expires_at:
        raise ValueError("Verification authorization has expired")
    policy = dict(payload.get("policy") or {})
    if policy.get("non_production") is not True or policy.get("allow_destructive_actions") is True:
        raise ValueError("Verification authorization violates the non-production safety policy")
    return {
        **policy,
        "authorization_id": str(payload.get("authorization_id", "")),
        "authorization_expires_at": expires_at.isoformat(),
        "authorization_source": str(source),
        "_trusted_authorization_verified": True,
    }


def _state_root(value: str | None) -> Path:
    if value:
        return Path(value).resolve()
    configured = os.getenv("VIBE_SEC_STATE_HOME")
    return Path(configured).resolve() if configured else Path.home() / ".vibe-sec"


def _load_or_create_key(root: Path, *, create: bool = True) -> bytes:
    key_path = root / "authorization.key"
    if not key_path.exists():
        if not create:
            raise ValueError("Verification authorization key is unavailable")
        root.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(secrets.token_bytes(32))
        try:
            key_path.chmod(0o600)
        except OSError:
            pass
    key = key_path.read_bytes()
    if len(key) < 32:
        raise ValueError("Verification authorization key is invalid")
    return key


def _sign(payload: dict[str, Any], key: bytes) -> str:
    unsigned = {key_name: value for key_name, value in payload.items() if key_name != "signature"}
    data = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _require_outside_project(path: Path, project: Path) -> None:
    try:
        path.relative_to(project)
    except ValueError:
        return
    raise ValueError("Verification authorization must be stored outside the audited project")
