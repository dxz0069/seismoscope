"""Capability registry for local and container-backed security tools."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from .models import ToolRequest, ToolResult, ToolSpec


class ToolAdapter(Protocol):
    spec: ToolSpec

    async def execute(self, request: ToolRequest, context: Any) -> ToolResult:
        ...


class CallableToolAdapter:
    def __init__(
        self,
        spec: ToolSpec,
        callback: Callable[[ToolRequest, Any], Awaitable[ToolResult] | ToolResult],
    ):
        self.spec = spec
        self.callback = callback

    async def execute(self, request: ToolRequest, context: Any) -> ToolResult:
        result = self.callback(request, context)
        result = await result if inspect.isawaitable(result) else result
        if not isinstance(result, ToolResult):
            raise TypeError(f"Tool {self.spec.name} returned {type(result).__name__}, expected ToolResult")
        return result


class ToolRegistry:
    def __init__(self):
        self._adapters: dict[str, ToolAdapter] = {}
        self._aliases: dict[str, str] = {}

    def register(self, adapter: ToolAdapter) -> None:
        name = adapter.spec.name
        if name in self._adapters or name in self._aliases:
            raise ValueError(f"Tool already registered: {name}")
        self._adapters[name] = adapter
        for alias in adapter.spec.aliases:
            if alias in self._adapters or alias in self._aliases:
                raise ValueError(f"Tool alias already registered: {alias}")
            self._aliases[alias] = name

    def get(self, name: str) -> ToolAdapter | None:
        return self._adapters.get(self._aliases.get(name, name))

    def specs(self) -> list[ToolSpec]:
        return [adapter.spec for adapter in self._adapters.values()]

    def openai_schemas(self, *, names: list[str] | None = None) -> list[dict[str, Any]]:
        selected = set(names or [])
        return [
            spec.to_openai_schema()
            for spec in self.specs()
            if not selected or spec.name in selected
        ]
