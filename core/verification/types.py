"""Canonical vulnerability-type names shared by verification paths."""

from __future__ import annotations

from typing import Dict

VULNERABILITY_TYPE_ALIASES: dict[str, str] = {
    "hardcoded_secrets": "secret_leak",
    "hardcoded_secret": "secret_leak",
    "hardcoded_credentials": "credential_exposure",
    "hardcoded_credential": "credential_exposure",
    "mcp_tool_poisoning": "mcp_insecurity",
}


def canonical_vulnerability_type(value: object) -> str:
    """Normalize an audit-reported vulnerability type for predicate selection."""
    reported = str(value or "unknown").lower()
    return VULNERABILITY_TYPE_ALIASES.get(reported, reported)
