"""Bounded ReAct-style task loop with tools, validation, nudge and resume hooks."""

from __future__ import annotations

import asyncio
import inspect
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..agents.base import AgentResult, TaskHandoff
from .completion import CompletionValidationResult, CompletionValidator
from .guard import AgentGuard
from .retry import RetryPolicy
from .state_machine import AgentRuntimeState, StateTransition, TaskStateMachine
from .stop_hooks import StopHookPolicy
from .task import AgentTask


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str | None = None


@dataclass
class TaskTurn:
    output: dict[str, Any] = field(default_factory=dict)
    done: bool = False
    next_state: AgentRuntimeState | None = None
    tool_call: ToolCall | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    handoff: TaskHandoff | None = None
    tokens_used: int = 0
    retryable: bool = True
    reason: str = ""
    terminal_action: str | None = None

    @classmethod
    def from_any(cls, raw: Any) -> TaskTurn:
        if isinstance(raw, cls):
            return raw
        if isinstance(raw, AgentResult):
            return cls(
                output=dict(raw.data),
                done=bool(raw.success),
                next_state=None if raw.success else AgentRuntimeState.FAILED,
                tokens_used=int(raw.tokens_used or raw.metadata.get("tokens_used", 0)),
                handoff=raw.handoff,
                reason=str(raw.metadata.get("error", "")),
                retryable=bool(raw.metadata.get("retryable", True)),
                terminal_action=raw.metadata.get("terminal_action"),
            )
        if not isinstance(raw, dict):
            raise TypeError("Agent task handler must return TaskTurn, AgentResult, or dict")

        nested = raw.get("result")
        if isinstance(nested, AgentResult):
            turn = cls.from_any(nested)
            turn.output = dict(raw.get("output", turn.output))
            turn.done = bool(raw.get("done", turn.done))
            turn.terminal_action = raw.get("terminal_action", turn.terminal_action)
            turn.reason = str(raw.get("reason", turn.reason))
            if raw.get("next_state"):
                turn.next_state = AgentRuntimeState(raw["next_state"])
            return turn

        tool = cls._parse_tool_call(raw.get("tool_call"))
        raw_tool_calls = raw.get("tool_calls") or []
        if not isinstance(raw_tool_calls, list):
            raw_tool_calls = [raw_tool_calls]
        tool_calls = [
            parsed for parsed in (cls._parse_tool_call(item) for item in raw_tool_calls)
            if parsed is not None
        ]
        if tool is not None and not tool_calls:
            tool_calls = [tool]
        if tool is None and tool_calls:
            tool = tool_calls[0]
        next_state = raw.get("next_state")
        if next_state:
            next_state = AgentRuntimeState(next_state)
        status = str(raw.get("status", "")).lower()
        done = bool(raw.get("done", status in {"done", "completed", "complete"}))
        if status in {"needs_tool", "waiting_tool"}:
            done = False
            next_state = AgentRuntimeState.WAITING_TOOL
        elif status in {"handoff", "waiting_handoff", "needs_handoff"}:
            done = False
            next_state = AgentRuntimeState.WAITING_HANDOFF
        elif status in {"failed", "error"}:
            done = False
            next_state = AgentRuntimeState.FAILED
        # Prefer explicit 'output' or 'data' keys; warn when falling back to the
        # raw dict itself so handler bugs surface at the point of return rather
        # than silently propagating wrong data to later stages.
        if "output" in raw:
            output_value = dict(raw["output"]) if isinstance(raw["output"], dict) else {"value": raw["output"]}
        elif "data" in raw:
            output_value = dict(raw["data"]) if isinstance(raw["data"], dict) else {"value": raw["data"]}
        else:
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "TaskTurn.from_any: handler returned a dict with neither 'output' nor 'data' key; "
                "using the entire dict as output. This is likely a handler implementation bug."
            )
            output_value = dict(raw)
        return cls(
            output=output_value,
            done=done,
            next_state=next_state,
            tool_call=tool,
            tool_calls=tool_calls,
            handoff=raw.get("handoff"),
            tokens_used=int(raw.get("tokens_used", 0) or 0),
            retryable=bool(raw.get("retryable", True)),
            reason=str(raw.get("reason", raw.get("error", ""))),
            terminal_action=raw.get("terminal_action"),
        )

    @staticmethod
    def _parse_tool_call(value: Any) -> ToolCall | None:
        if isinstance(value, ToolCall):
            return value
        if isinstance(value, str):
            return ToolCall(name=value)
        if isinstance(value, dict):
            return ToolCall(
                name=str(value.get("name", "")),
                arguments=dict(value.get("arguments", value.get("input", {}))),
                call_id=value.get("id") or value.get("call_id"),
            )
        return None


@dataclass
class TaskLoopResult:
    status: str
    task: AgentTask
    output: dict[str, Any] = field(default_factory=dict)
    turns: int = 0
    error: str | None = None
    completion: CompletionValidationResult | None = None


class LoopDetector:
    def __init__(self, repeat_limit: int = 3):
        self.repeat_limit = max(1, int(repeat_limit))
        self._counts: dict[str, int] = {}

    def observe(self, value: Any) -> int:
        try:
            key = json.dumps(value, sort_keys=True, default=str)
        except (TypeError, ValueError):
            key = repr(value)
        self._counts[key] = self._counts.get(key, 0) + 1
        return self._counts[key]


Handler = Callable[[AgentTask, dict[str, Any]], Any]


class AgentTaskLoop:
    """Execute one task until a validated terminal state or a bounded stop."""

    def __init__(
        self,
        *,
        retry_policy: RetryPolicy | None = None,
        completion_validator: CompletionValidator | None = None,
        guard: AgentGuard | None = None,
        max_turns: int = 20,
        max_tokens: int = 0,
        timeout_seconds: float = 0,
        loop_repeat_limit: int = 3,
        max_completion_nudges: int = 2,
        require_terminal_action: bool | None = None,
        checkpoint_sink: Callable[..., Any] | None = None,
        transition_sink: Callable[..., Any] | None = None,
    ):
        self.retry_policy = retry_policy or RetryPolicy()
        self.completion_validator = completion_validator or CompletionValidator()
        self.guard = guard or AgentGuard()
        self.max_turns = max(1, int(max_turns))
        self.max_tokens = max(0, int(max_tokens))
        self.timeout_seconds = max(0.0, float(timeout_seconds))
        self.loop_repeat_limit = max(1, int(loop_repeat_limit))
        self.max_completion_nudges = max(0, int(max_completion_nudges))
        self.require_terminal_action = require_terminal_action
        self.stop_hook_policy = StopHookPolicy(require_terminal_action=bool(require_terminal_action))
        self.checkpoint_sink = checkpoint_sink
        self.transition_sink = transition_sink
        self._stop_requested = False
        self._pause_requested = False

    def request_stop(self) -> None:
        self._stop_requested = True

    def request_pause(self) -> None:
        self._pause_requested = True

    def request_resume(self) -> None:
        self._pause_requested = False
        self._stop_requested = False

    async def run(
        self,
        task: AgentTask,
        handler: Handler,
        *,
        context: dict[str, Any] | None = None,
        tool_executor: Callable[..., Any] | None = None,
        resume: bool = False,
    ) -> TaskLoopResult:
        if task.status == AgentRuntimeState.PAUSED and not resume:
            return TaskLoopResult("paused", task, turns=task.turn_count)
        self.request_resume() if resume else None
        machine = TaskStateMachine(state=task.status, sink=self._transition_event)
        machine.history = [StateTransition.from_dict(item) for item in task.state_history]
        context = {**dict(task.metadata.get("loop_context", {})), **dict(context or {})}
        if isinstance(context.get("pending_tool_call"), dict):
            context["pending_tool_call"] = TaskTurn._parse_tool_call(context["pending_tool_call"])
        if isinstance(context.get("pending_tool_calls"), list):
            context["pending_tool_calls"] = [
                parsed for parsed in (
                    TaskTurn._parse_tool_call(item)
                    for item in context["pending_tool_calls"]
                )
                if parsed is not None
            ]
        saved_handler_state = task.metadata.get("handler_state")
        if saved_handler_state and hasattr(handler, "restore_state"):
            handler.restore_state(saved_handler_state)
        detector = LoopDetector(self.loop_repeat_limit)
        started = time.monotonic()
        output: dict[str, Any] = {}
        completion = None

        if machine.state == AgentRuntimeState.CREATED:
            self._move(machine, task, AgentRuntimeState.PLANNED, "task accepted")
            self._move(machine, task, AgentRuntimeState.DISPATCHED, "task dispatched")
            self._move(machine, task, AgentRuntimeState.RUNNING, "task started")
        elif machine.state == AgentRuntimeState.FAILED:
            self._move(machine, task, AgentRuntimeState.DISPATCHED, "task resumed")
            self._move(machine, task, AgentRuntimeState.RUNNING, "task resumed")
        elif machine.state == AgentRuntimeState.PAUSED:
            paused_from_value = task.metadata.pop("paused_from", AgentRuntimeState.RUNNING.value)
            try:
                paused_from = AgentRuntimeState(paused_from_value)
            except ValueError:
                paused_from = AgentRuntimeState.RUNNING
            if paused_from not in {
                AgentRuntimeState.RUNNING,
                AgentRuntimeState.WAITING_TOOL,
                AgentRuntimeState.WAITING_HANDOFF,
                AgentRuntimeState.VERIFYING,
            }:
                paused_from = AgentRuntimeState.RUNNING
            self._move(machine, task, paused_from, f"task resumed to {paused_from.value}")
        elif machine.state == AgentRuntimeState.WAITING_HANDOFF:
            self._move(machine, task, AgentRuntimeState.RUNNING, "handoff resumed")

        while not machine.is_terminal:
            if self._stop_requested:
                self._move(machine, task, AgentRuntimeState.STOPPED, "stop requested")
                return TaskLoopResult("stopped", task, output, task.turn_count)
            if self._pause_requested:
                task.metadata["paused_from"] = machine.state.value
                self._move(machine, task, AgentRuntimeState.PAUSED, "pause requested")
                return TaskLoopResult("paused", task, output, task.turn_count)
            if self.timeout_seconds and time.monotonic() - started >= self.timeout_seconds:
                return await self._fail(task, machine, "task timeout")
            if task.turn_count >= self.max_turns:
                return await self._fail(task, machine, "maximum turn limit reached")
            if self.max_tokens and task.total_tokens >= self.max_tokens:
                return await self._fail(task, machine, "maximum token budget reached")

            if machine.state == AgentRuntimeState.WAITING_TOOL:
                if not tool_executor:
                    return await self._fail(task, machine, "tool requested but no tool executor is configured")
                pending_calls = context.get("pending_tool_calls")
                if pending_calls is not None:
                    tool_call = pending_calls.pop(0) if pending_calls else None
                    if pending_calls:
                        context["pending_tool_calls"] = pending_calls
                    else:
                        context.pop("pending_tool_calls", None)
                else:
                    tool_call = context.pop("pending_tool_call", None)
                try:
                    tool_output = await self._invoke_tool(tool_executor, tool_call, context)
                    context.setdefault("tool_results", []).append(
                        {
                            "tool": tool_call.name,
                            "tool_call_id": tool_call.call_id,
                            "output": tool_output,
                        }
                    )
                    self._persist_runtime_context(task, context)
                    self._checkpoint(task, "tool_completed", {"tool_output": tool_output})
                except Exception as exc:
                    tool_error = {"error": str(exc), "status": "failed"}
                    context.setdefault("tool_results", []).append({
                        "tool": tool_call.name if tool_call else "unknown",
                        "tool_call_id": tool_call.call_id if tool_call else None,
                        "output": tool_error,
                    })
                    task.last_error = str(exc)
                    self._persist_runtime_context(task, context)
                    self._checkpoint(task, "tool_failed", {"tool_output": tool_error})
                if context.get("pending_tool_calls"):
                    continue
                self._move(machine, task, AgentRuntimeState.RUNNING, "tool result received")
                continue

            task.turn_count += 1
            try:
                raw = await self._invoke_handler(handler, task, context)
                turn = TaskTurn.from_any(raw)
                task.total_tokens += turn.tokens_used
                output = turn.output
                if turn.handoff:
                    task.handoff = turn.handoff
                task.next_action = turn.reason
                self._persist_handler_state(task, handler)
                self._persist_runtime_context(task, context)
                self._checkpoint(task, "turn_completed", {"turn": task.turn_count, "output": output})
            except Exception as exc:
                if await self._retry_error(task, machine, exc):
                    continue
                return TaskLoopResult("failed", task, turns=task.turn_count, error=str(exc))

            # A provider tool call must receive its matching tool response before
            # any guard nudge or another model request can be appended.
            if turn.tool_calls or turn.tool_call:
                tool_calls = list(turn.tool_calls or ([turn.tool_call] if turn.tool_call else []))
                if len(tool_calls) == 1:
                    context["pending_tool_call"] = tool_calls[0]
                else:
                    context["pending_tool_calls"] = tool_calls
                self._persist_runtime_context(task, context)
                self._move(machine, task, AgentRuntimeState.WAITING_TOOL, "tool requested")
                continue

            guard_decision = self.guard.evaluate(output, {**context, "task": task.to_dict()})
            if not guard_decision.allowed:
                nudges = int(task.metadata.get("guard_nudges", 0)) + 1
                task.metadata["guard_nudges"] = nudges
                context["guard_feedback"] = guard_decision.reason
                if nudges > self.max_completion_nudges:
                    self._move(machine, task, AgentRuntimeState.WAITING_HANDOFF, "guard blocked completion")
                    return TaskLoopResult("waiting_handoff", task, output, task.turn_count)
                self._move(machine, task, AgentRuntimeState.RUNNING, "guard nudge")
                continue

            repeat_count = detector.observe({"output": output, "next": turn.next_state, "done": turn.done})
            if repeat_count > self.loop_repeat_limit:
                nudges = int(task.metadata.get("loop_nudges", 0)) + 1
                task.metadata["loop_nudges"] = nudges
                context["loop_feedback"] = "The same action repeated. Inspect a new surface or provide evidence."
                if nudges > 1:
                    self._move(machine, task, AgentRuntimeState.WAITING_HANDOFF, "agent loop detected")
                    return TaskLoopResult("waiting_handoff", task, output, task.turn_count)
                self._move(machine, task, AgentRuntimeState.RUNNING, "loop detector nudge")
                continue

            contract_name = str((task.completion_contract or {}).get("name", ""))
            terminal_decision = self.stop_hook_policy.evaluate(
                done=turn.done,
                terminal_action=turn.terminal_action,
                contract_name=contract_name,
            )
            if not terminal_decision.allowed:
                nudges = int(task.metadata.get("terminal_action_nudges", 0)) + 1
                task.metadata["terminal_action_nudges"] = nudges
                context["terminal_action_feedback"] = terminal_decision.message
                if nudges > self.max_completion_nudges:
                    self._move(machine, task, AgentRuntimeState.WAITING_HANDOFF, "terminal action missing")
                    return TaskLoopResult("waiting_handoff", task, output, task.turn_count)
                self._move(machine, task, AgentRuntimeState.RUNNING, "continue-terminal nudge")
                continue

            if turn.next_state == AgentRuntimeState.WAITING_HANDOFF:
                self._move(machine, task, AgentRuntimeState.WAITING_HANDOFF, turn.reason or "handoff requested")
                return TaskLoopResult("waiting_handoff", task, output, task.turn_count)
            if turn.next_state == AgentRuntimeState.FAILED:
                error = RuntimeError(turn.reason or "agent failed")
                if await self._retry_error(task, machine, error):
                    continue
                return TaskLoopResult("failed", task, output, task.turn_count, error=str(error))

            if not turn.done:
                self._move(machine, task, AgentRuntimeState.RUNNING, "continue turn")
                continue

            self._move(machine, task, AgentRuntimeState.VERIFYING, "completion requested")
            contract = task.completion_contract or None
            completion = self.completion_validator.validate(
                contract,
                output,
                evidence_refs=task.evidence_refs,
            )
            if completion.valid:
                self._move(machine, task, AgentRuntimeState.COMPLETED, "completion contract accepted")
                return TaskLoopResult("completed", task, output, task.turn_count, completion=completion)

            nudges = int(task.metadata.get("completion_nudges", 0)) + 1
            task.metadata["completion_nudges"] = nudges
            context["completion_feedback"] = completion.feedback
            if nudges > self.max_completion_nudges:
                self._move(machine, task, AgentRuntimeState.WAITING_HANDOFF, "completion contract rejected")
                return TaskLoopResult("waiting_handoff", task, output, task.turn_count, completion=completion)
            self._move(machine, task, AgentRuntimeState.RUNNING, "completion nudge")

        return TaskLoopResult("failed", task, output, task.turn_count, error="unexpected terminal state")

    async def _retry_error(
        self,
        task: AgentTask,
        machine: TaskStateMachine,
        error: BaseException,
    ) -> bool:
        task.last_error = str(error)
        if machine.state != AgentRuntimeState.FAILED:
            self._move(machine, task, AgentRuntimeState.FAILED, "recoverable task error", {"error": str(error)})
        allowed_attempts = min(self.retry_policy.max_attempts, max(1, task.max_attempts))
        if task.attempt < allowed_attempts and self.retry_policy.should_retry(task.attempt, error):
            task.attempt += 1
            self._move(machine, task, AgentRuntimeState.DISPATCHED, "retry scheduled")
            self._move(machine, task, AgentRuntimeState.RUNNING, "retry started")
            await self.retry_policy.wait(task.attempt)
            return True
        task.attempt = max(task.attempt, self.retry_policy.max_attempts)
        return False

    async def _fail(self, task: AgentTask, machine: TaskStateMachine, error: str) -> TaskLoopResult:
        task.last_error = error
        if machine.state not in {AgentRuntimeState.FAILED, AgentRuntimeState.STOPPED}:
            self._move(machine, task, AgentRuntimeState.FAILED, error)
        return TaskLoopResult("failed", task, turns=task.turn_count, error=error)

    def _move(
        self,
        machine: TaskStateMachine,
        task: AgentTask,
        state: AgentRuntimeState,
        reason: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        machine.transition(state, reason=reason, data=data)
        task.sync_state(machine)
        self._checkpoint(task, "state_transition", {"reason": reason})

    def _transition_event(self, transition) -> None:
        if self.transition_sink:
            self.transition_sink(transition)

    def _checkpoint(self, task: AgentTask, reason: str, data: dict[str, Any] | None = None) -> None:
        if not self.checkpoint_sink:
            return
        payload = {"reason": reason, "task": task.to_dict(), **dict(data or {})}
        try:
            result = self.checkpoint_sink(task, payload)
            if inspect.isawaitable(result):
                # Checkpoint sinks must be synchronous. If an async sink is passed,
                # we schedule the coroutine but attach a done-callback to log failures
                # rather than silently swallowing them.
                import logging as _logging
                _loop_logger = _logging.getLogger(__name__)

                async def _guarded(coro, _logger=_loop_logger, _reason=reason):
                    try:
                        await coro
                    except Exception as exc:  # noqa: BLE001
                        _logger.warning("Async checkpoint sink failed (reason=%s): %s", _reason, exc)

                asyncio.create_task(_guarded(result))
        except Exception as exc:  # noqa: BLE001
            import logging as _logging
            _logging.getLogger(__name__).warning("Checkpoint sink raised (reason=%s): %s", reason, exc)

    @staticmethod
    def _persist_handler_state(task: AgentTask, handler: Any) -> None:
        if hasattr(handler, "to_state"):
            task.metadata["handler_state"] = handler.to_state()

    @staticmethod
    def _persist_runtime_context(task: AgentTask, context: dict[str, Any]) -> None:
        safe_context = {}
        for key in (
            "tool_results",
            "pending_tool_call",
            "pending_tool_calls",
            "guard_feedback",
            "completion_feedback",
            "loop_feedback",
            "terminal_action_feedback",
        ):
            if key in context:
                try:
                    value = context[key]
                    if isinstance(value, ToolCall):
                        value = AgentTaskLoop._tool_call_to_dict(value)
                    elif isinstance(value, list):
                        value = [
                            AgentTaskLoop._tool_call_to_dict(item) if isinstance(item, ToolCall) else item
                            for item in value
                        ]
                    safe_context[key] = json.loads(json.dumps(value, default=str))
                except (TypeError, ValueError):
                    safe_context[key] = str(context[key])
        task.metadata["loop_context"] = safe_context

    @staticmethod
    def _tool_call_to_dict(value: ToolCall) -> dict[str, Any]:
        return {
            "name": value.name,
            "arguments": value.arguments,
            "id": value.call_id,
        }

    async def _invoke_handler(self, handler: Handler, task: AgentTask, context: dict[str, Any]) -> Any:
        result = handler(task, context)
        return await result if inspect.isawaitable(result) else result

    async def _invoke_tool(self, executor: Callable[..., Any], call: ToolCall, context: dict[str, Any]) -> Any:
        if call is None:
            raise RuntimeError("Missing pending tool call")
        if hasattr(executor, "execute"):
            result = executor.execute(name=call.name, arguments=call.arguments, context=context)
            return await result if inspect.isawaitable(result) else result
        try:
            result = executor(call.name, call.arguments, context)
        except TypeError:
            result = executor(call.name, call.arguments)
        return await result if inspect.isawaitable(result) else result
