"""Capability registry for local and container-backed security tools."""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol

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
        self._adapters: Dict[str, ToolAdapter] = {}
        self._aliases: Dict[str, str] = {}

    def register(self, adapter: ToolAdapter) -> None:
        name = adapter.spec.name
        if name in self._adapters or name in self._aliases:
            raise ValueError(f"Tool already registered: {name}")
        self._adapters[name] = adapter
        for alias in adapter.spec.aliases:
            if alias in self._adapters or alias in self._aliases:
                raise ValueError(f"Tool alias already registered: {alias}")
            self._aliases[alias] = name

    def get(self, name: str) -> Optional[ToolAdapter]:
        return self._adapters.get(self._aliases.get(name, name))

    def specs(self) -> List[ToolSpec]:
        return [adapter.spec for adapter in self._adapters.values()]

    def openai_schemas(self, *, names: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        selected = set(names or [])
        return [
            spec.to_openai_schema()
            for spec in self.specs()
            if not selected or spec.name in selected
        ]
