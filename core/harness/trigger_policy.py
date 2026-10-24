"""Compatibility import for hosts that load trigger policy from harness."""

from ..policy.trigger_policy import TriggerDecision, TriggerPolicy

__all__ = ["TriggerDecision", "TriggerPolicy"]
