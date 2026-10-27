"""Shared redaction and JSON-safe persistence helpers."""

from __future__ import annotations

import hashlib
import re
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

SENSITIVE_KEY_PARTS = (
    "api_key", "apikey", "access_key", "token", "password", "passwd",
    "secret", "credential", "private_key", "client_secret",
)

_KEY_NAME = (
    r"(?:api[_-]?key|access[_-]?key|token|password|passwd|pwd|secret(?:_key)?|"
    r"client[_-]?secret|authorization)"
)
_QUOTED_ASSIGNMENT = re.compile(
    rf"(?P<prefix>(?:['\"]?{_KEY_NAME}['\"]?)"
    rf"(?:\s*:\s*[A-Za-z_][\w\[\], .|]*\s*=|\s*[:=])\s*)"
    r"(?P<quote>['\"])(?P<value>[^'\"\r\n]{4,})(?P=quote)",
    re.IGNORECASE,
)
_UNQUOTED_ASSIGNMENT = re.compile(
    rf"(?P<prefix>(?:['\"]?{_KEY_NAME}['\"]?)\s*[:=]\s*)"
    r"(?P<value>(?!['\"]?\[REDACTED)[^\s,#}\]]{8,})",
    re.IGNORECASE,
)
_TOKEN_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}"),
)


def _marker(secret: str) -> str:
    digest = hashlib.sha256(secret.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"[REDACTED sha256:{digest} len:{len(secret)}]"


def redact_sensitive_text(value: str) -> str:
    """Redact common credential literals while retaining a stable fingerprint."""
    text = str(value)

    def quoted(match: re.Match[str]) -> str:
        secret = match.group("value")
        if secret.startswith("[REDACTED"):
            return match.group(0)
        quote = match.group("quote")
        return f"{match.group('prefix')}{quote}{_marker(secret)}{quote}"

    def unquoted(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}{_marker(match.group('value'))}"

    text = _QUOTED_ASSIGNMENT.sub(quoted, text)
    text = _UNQUOTED_ASSIGNMENT.sub(unquoted, text)
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(lambda match: _marker(match.group(0)), text)
    return text


def sanitize_for_persistence(value: Any) -> Any:
    """Convert domain objects to JSON-safe values and redact sensitive content."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, bytes):
        return redact_sensitive_text(value.decode("utf-8", errors="replace"))
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Enum):
        return sanitize_for_persistence(value.value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = str(key)
            lowered = normalized_key.lower()
            if any(part in lowered for part in SENSITIVE_KEY_PARTS) and isinstance(
                item, (str, bytes, dict, list, tuple, set),
            ):
                sanitized[normalized_key] = "[REDACTED]"
            else:
                sanitized[normalized_key] = sanitize_for_persistence(item)
        return sanitized
    if isinstance(value, (list, tuple, set)):
        return [sanitize_for_persistence(item) for item in value]
    if hasattr(value, "to_dict"):
        return sanitize_for_persistence(value.to_dict())
    return redact_sensitive_text(repr(value))
