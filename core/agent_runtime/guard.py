"""Adapter that turns ReasoningGuard observations into loop decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class GuardDecision:
    allowed: bool
    action: str = "continue"
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)


class AgentGuard:
    """Use the existing ReasoningGuard without coupling the runtime to it."""

    def __init__(self, reasoning_guard=None):
        self.reasoning_guard = reasoning_guard

    def evaluate(self, output: dict[str, Any], context: dict[str, Any]) -> GuardDecision:
        if self.reasoning_guard is None:
            return GuardDecision(allowed=True)

        if hasattr(self.reasoning_guard, "evaluate"):
            raw = self.reasoning_guard.evaluate(output, context)
            if isinstance(raw, GuardDecision):
                return raw
            if isinstance(raw, dict):
                return GuardDecision(
                    allowed=bool(raw.get("allowed", raw.get("status") != "blocked")),
                    action=str(raw.get("action", "continue")),
                    reason=str(raw.get("reason", "")),
                    details=dict(raw),
                )

        monitor = getattr(self.reasoning_guard, "monitor", None)
        if monitor is None:
            return GuardDecision(allowed=True)
        finding = output.get("finding", output)
        evidence = output.get("evidence_bundle") or output.get("evidence") or {}
        if isinstance(evidence, list):
            evidence = {"items": evidence, "gaps": []}
        result = monitor(finding, evidence, context)
        anomalies = [getattr(item, "value", str(item)) for item in result.anomalies]
        return GuardDecision(
            allowed=result.status != "blocked",
            action="nudge" if result.status == "blocked" else "continue",
            reason="; ".join(anomalies),
            details={
                "status": result.status,
                "lane": getattr(result.lane, "value", str(result.lane)),
                "confidence_score": result.confidence_score,
                "anomalies": anomalies,
            },
        )
