"""Parent/child task graph controller for parallel agent work."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from collections.abc import Iterable

from .loop import AgentTaskLoop, TaskLoopResult
from .task import AgentTask


@dataclass
class GraphTask:
    task: AgentTask
    handler: Any
    depends_on: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskGraphResult:
    status: str
    tasks: dict[str, TaskLoopResult]
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def completed(self) -> list[TaskLoopResult]:
        return [item for item in self.tasks.values() if item.status == "completed"]


class TaskGraphController:
    """Run independent children concurrently while honoring dependencies."""

    def __init__(self, *, max_concurrency: int = 4, loop_factory=None):
        self.max_concurrency = max(1, int(max_concurrency))
        self.loop_factory = loop_factory or (lambda: AgentTaskLoop())
        self._nodes: dict[str, GraphTask] = {}
        self._stop_requested = False
        self._active_loops: dict[str, AgentTaskLoop] = {}

    def add_task(
        self,
        task: AgentTask,
        handler,
        *,
        depends_on: Iterable[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        if task.task_id in self._nodes:
            raise ValueError(f"Duplicate graph task: {task.task_id}")
        self._nodes[task.task_id] = GraphTask(
            task=task,
            handler=handler,
            depends_on=list(depends_on or []),
            context=dict(context or {}),
        )

    def request_stop(self) -> None:
        self._stop_requested = True
        for loop in self._active_loops.values():
            loop.request_stop()

    async def run(self, *, context: dict[str, Any] | None = None) -> TaskGraphResult:
        self._validate_dependencies()
        results: dict[str, TaskLoopResult] = {}
        errors: dict[str, str] = {}
        pending = set(self._nodes)
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def execute(node: GraphTask) -> TaskLoopResult:
            async with semaphore:
                loop = self.loop_factory()
                self._active_loops[node.task.task_id] = loop
                try:
                    return await loop.run(
                        node.task,
                        node.handler,
                        context={**dict(context or {}), **node.context},
                    )
                finally:
                    self._active_loops.pop(node.task.task_id, None)

        while pending:
            if self._stop_requested:
                for task_id in pending:
                    errors[task_id] = "graph stop requested"
                break
            ready = [
                task_id
                for task_id in pending
                if all(dep in results for dep in self._nodes[task_id].depends_on)
            ]
            if not ready:
                raise RuntimeError("Task graph cannot make progress")

            runnable = []
            for task_id in ready:
                node = self._nodes[task_id]
                failed_deps = [
                    dep for dep in node.depends_on if results[dep].status != "completed"
                ]
                if failed_deps:
                    errors[task_id] = f"dependency failed: {', '.join(failed_deps)}"
                    results[task_id] = TaskLoopResult("skipped", node.task, error=errors[task_id])
                    pending.remove(task_id)
                else:
                    runnable.append(task_id)

            if runnable:
                completed = await asyncio.gather(
                    *(execute(self._nodes[task_id]) for task_id in runnable),
                    return_exceptions=True,
                )
                for task_id, result in zip(runnable, completed, strict=True):
                    if isinstance(result, Exception):
                        errors[task_id] = str(result)
                        results[task_id] = TaskLoopResult(
                            "failed", self._nodes[task_id].task, error=str(result)
                        )
                    else:
                        results[task_id] = result
                        if result.status != "completed":
                            errors[task_id] = result.error or f"task ended with {result.status}"
                    pending.remove(task_id)

        status = "completed" if not errors and all(item.status == "completed" for item in results.values()) else "failed"
        return TaskGraphResult(status=status, tasks=results, errors=errors)

    def _validate_dependencies(self) -> None:
        for node in self._nodes.values():
            unknown = set(node.depends_on) - set(self._nodes)
            if unknown:
                raise ValueError(f"Unknown task dependencies for {node.task.task_id}: {sorted(unknown)}")
