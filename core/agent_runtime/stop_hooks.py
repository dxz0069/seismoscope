"""Terminal-action stop hooks inspired by AutoCVE's continue-terminal guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class StopHookDecision:
    allowed: bool
    action: str = "continue"
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)


class StopHookPolicy:
    """Keep a task running until it emits the required terminal action."""

    def __init__(self, *, require_terminal_action: bool = False):
        self.require_terminal_action = require_terminal_action

    def evaluate(self, *, done: bool, terminal_action: str | None, contract_name: str = "") -> StopHookDecision:
        required = self.require_terminal_action or bool(contract_name)
        if not done or not required:
            return StopHookDecision(allowed=True)
        if terminal_action:
            return StopHookDecision(allowed=True, action="terminal", details={"terminal_action": terminal_action})
        return StopHookDecision(
            allowed=False,
            action="nudge",
            message=(
                f"The {contract_name or 'agent'} task claimed completion without a terminal action. "
                "Continue the investigation and call the required Finalize tool."
            ),
            details={"contract": contract_name, "reason": "missing_terminal_action"},
        )
