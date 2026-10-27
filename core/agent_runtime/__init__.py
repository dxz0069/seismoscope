"""Reusable agent execution primitives for the security harness."""

from .completion import (
    CompletionValidationResult,
    CompletionValidator,
    FinalizeAuditDiscoveryContract,
    FinalizeFindingContract,
    FinalizeTaskContract,
    FinalizeVerificationContract,
)
from .context import ContextWindow
from .graph import TaskGraphController, TaskGraphResult
from .loop import AgentTaskLoop, TaskLoopResult, TaskTurn, ToolCall
from .react import ReActConfig, ReActHandler
from .resume import ResumeManager
from .retry import RetryPolicy
from .state_machine import (
    AgentRuntimeState,
    InvalidTransitionError,
    StateTransition,
    TaskStateMachine,
)
from .stop_hooks import StopHookDecision, StopHookPolicy
from .task import AgentTask
from .tool_guard import PermissionedToolExecutor, ToolExecutionRecord

__all__ = [
    "AgentRuntimeState",
    "AgentTask",
    "AgentTaskLoop",
    "ContextWindow",
    "CompletionValidationResult",
    "CompletionValidator",
    "FinalizeFindingContract",
    "FinalizeAuditDiscoveryContract",
    "FinalizeTaskContract",
    "FinalizeVerificationContract",
    "InvalidTransitionError",
    "RetryPolicy",
    "ReActConfig",
    "ReActHandler",
    "ResumeManager",
    "StateTransition",
    "StopHookDecision",
    "StopHookPolicy",
    "TaskGraphController",
    "TaskGraphResult",
    "PermissionedToolExecutor",
    "ToolExecutionRecord",
    "TaskLoopResult",
    "TaskStateMachine",
    "TaskTurn",
    "ToolCall",
]
