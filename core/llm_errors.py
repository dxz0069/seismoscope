"""Sanitized categories for LLM runtime failures."""

from __future__ import annotations

from typing import Any


def classify_llm_failure(error: Any) -> str:
    """Classify an LLM failure without retaining provider response text."""
    message = str(error or "").lower()
    if not message:
        return "react_session_incomplete"
    if "401" in message or "authentication" in message or "api key" in message:
        return "authentication_failed"
    if "403" in message or "permission" in message:
        return "permission_denied"
    if "rate limit" in message or "429" in message:
        return "rate_limited"
    if "maximum turn" in message:
        return "turn_limit_reached"
    if "maximum token" in message or "token budget" in message:
        return "token_limit_reached"
    if "timeout" in message:
        return "timeout"
    if "400" in message or "badrequest" in message:
        return "provider_bad_request"
    if "finalize" in message or "terminal action" in message:
        return "terminal_contract_unmet"
    return "provider_unavailable"
