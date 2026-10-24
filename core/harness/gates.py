"""Deterministic closure gates used before a finding is considered closed."""

from typing import Any, Dict, Optional

# Canonical regression status value.  Some upstream components emit "success"
# instead of "passed"; normalise at the gate rather than fixing every producer.
_PASSING_REGRESSION_STATUSES = {"passed", "success"}


def normalize_regression_status(value: Optional[str]) -> Optional[str]:
    """Map legacy 'success' to the canonical 'passed'; leave other values as-is."""
    if value in _PASSING_REGRESSION_STATUSES:
        return "passed"
    return value


def can_close_finding(
    finding: Dict[str, Any],
    *,
    require_retest: bool = True,
) -> bool:
    """Return True only when all harness-owned closure predicates are satisfied.

    A model assertion alone cannot close a finding.  The caller should pass the
    full finding dict including ``evidence_bundle`` and ``regression_status``.

    Raises TypeError if *finding* is not a dict so callers discover schema bugs
    immediately rather than getting a silent False.
    """
    if not isinstance(finding, dict):
        raise TypeError(f"can_close_finding expects a dict, got {type(finding).__name__!r}")

    if finding.get("verification_status") != "verified":
        return False

    evidence = finding.get("evidence_bundle", {})
    if not isinstance(evidence, dict):
        return False
    items = evidence.get("items") or []
    # Require at least one non-empty, non-None evidence item
    meaningful_items = [item for item in items if item]
    if not meaningful_items:
        return False
    if evidence.get("gaps"):
        return False

    if require_retest:
        raw_status = finding.get("regression_status")
        if normalize_regression_status(raw_status) != "passed":
            return False

    return True


def close_reason(finding: Dict[str, Any], *, require_retest: bool = True) -> str:
    """Return a human-readable reason string for the closure decision.

    Returns an empty string when the finding CAN be closed (i.e. the gate
    passed), or a short diagnostic when it cannot.
    """
    if not isinstance(finding, dict):
        return "finding is not a dict"
    if finding.get("verification_status") != "verified":
        return f"verification_status is {finding.get('verification_status')!r}, expected 'verified'"
    evidence = finding.get("evidence_bundle", {}) or {}
    items = [item for item in (evidence.get("items") or []) if item]
    if not items:
        return "evidence_bundle.items is empty"
    if evidence.get("gaps"):
        return f"evidence_bundle has {len(evidence['gaps'])} unresolved gap(s)"
    if require_retest:
        raw_status = finding.get("regression_status")
        if normalize_regression_status(raw_status) != "passed":
            return f"regression_status is {raw_status!r}, expected 'passed'"
    return ""  # gate passed
