"""Checkpoint-backed task resume helpers for CLI and Skill integrations."""

from __future__ import annotations

from typing import Any, Dict, Optional
from collections.abc import Callable

from ..session.models import RunSession
from ..session.store import SessionStore
from .loop import AgentTaskLoop, TaskLoopResult
from .state_machine import AgentRuntimeState
from .task import AgentTask


class ResumeManager:
    def __init__(self, store: SessionStore):
        self.store = store

    def load_session(self, session_id: str) -> RunSession:
        return self.store.load(session_id)

    def load_task(self, session_id: str, task_id: str | None = None) -> AgentTask:
        session = self.store.load(session_id)
        for checkpoint in reversed(session.checkpoints):
            payload = checkpoint.state.get("task")
            if not payload:
                continue
            task = AgentTask.from_dict(payload)
            if task_id is None or task.task_id == task_id:
                return task
        raise LookupError(f"No task checkpoint found for session {session_id}")

    def save_task_checkpoint(
        self,
        session: RunSession,
        task: AgentTask,
        *,
        reason: str = "task checkpoint",
        data: dict[str, Any] | None = None,
    ) -> None:
        session.checkpoint(
            "agent_task",
            {"reason": reason, "task": task.to_dict(), **dict(data or {})},
        )

    async def resume_task(
        self,
        session_id: str,
        handler: Callable[..., Any],
        *,
        task_id: str | None = None,
        loop: AgentTaskLoop | None = None,
        context: dict[str, Any] | None = None,
        tool_executor: Callable[..., Any] | None = None,
    ) -> TaskLoopResult:
        session = self.store.load(session_id)
        task = self.load_task(session_id, task_id)
        if task.status in {AgentRuntimeState.COMPLETED, AgentRuntimeState.STOPPED}:
            return TaskLoopResult(task.status.value, task, turns=task.turn_count)
        loop = loop or AgentTaskLoop()
        old_sink = loop.checkpoint_sink

        def checkpoint_sink(current_task: AgentTask, payload: dict[str, Any]) -> None:
            self.save_task_checkpoint(session, current_task, data=payload)
            self.store.save(session)
            if old_sink:
                old_sink(current_task, payload)

        loop.checkpoint_sink = checkpoint_sink
        result = await loop.run(
            task,
            handler,
            context=context,
            tool_executor=tool_executor,
            resume=True,
        )
        self.store.save(session)
        return result

    async def retry_failed_task(self, session_id: str, handler: Callable[..., Any], **kwargs) -> TaskLoopResult:
        task = self.load_task(session_id, kwargs.get("task_id"))
        if task.status != AgentRuntimeState.FAILED:
            raise ValueError(f"Task {task.task_id} is not failed")
        return await self.resume_task(session_id, handler, **kwargs)

    async def resume_session(
        self,
        session_id: str,
        handler: Callable[..., Any],
        **kwargs,
    ) -> TaskLoopResult:
        """Resume the newest resumable task checkpoint in a session."""
        return await self.resume_task(session_id, handler, **kwargs)
