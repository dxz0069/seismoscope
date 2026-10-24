"""Closure policy for evidence-backed finding lifecycle."""

from typing import Any, Dict

from ..harness.gates import can_close_finding


class ClosurePolicy:
    def __init__(self, require_retest: bool = True):
        self.require_retest = require_retest

    def evaluate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        allowed = can_close_finding(finding, require_retest=self.require_retest)
        return {
            "allowed": allowed,
            "status": "closed" if allowed else "open",
            "reason": "Evidence and retest gates passed" if allowed else "Evidence or retest gate is incomplete",
        }
