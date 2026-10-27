"""LLM-backed ReAct turn handler used by finding and verification agents."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from ..llm_service import LLMMessage
from .context import ContextWindow


@dataclass
class ReActConfig:
    system_prompt: str = ""
    model: str | None = None
    temperature: float = 0.1
    max_tokens: int = 8192
    terminal_tools: Iterable[str] = field(
        default_factory=lambda: (
            "FinalizeTask",
            "FinalizeFinding",
            "FinalizeVerification",
            "FinalizeAuditDiscovery",
        )
    )
    max_context_messages: int = 80
    max_context_chars: int = 120_000
    force_terminal_after_tool_results: int = 0
    force_terminal_after_turn: int = 0
    minimum_tool_results_before_terminal: int = 1
    allow_terminal_json_fallback: bool = True


class ReActHandler:
    """Convert model tool calls into ``TaskTurn``-compatible dictionaries."""

    def __init__(
        self,
        llm_service,
        *,
        initial_messages: list[LLMMessage] | None = None,
        tool_schemas: list[dict[str, Any]] | None = None,
        config: ReActConfig | None = None,
    ):
        self.llm_service = llm_service
        self.config = config or ReActConfig()
        self.tool_schemas = list(tool_schemas or [])
        self.messages = list(initial_messages or [])
        self.context_window = ContextWindow(
            max_messages=self.config.max_context_messages,
            max_chars=self.config.max_context_chars,
        )
        if self.config.system_prompt and not any(item.role == "system" for item in self.messages):
            self.messages.insert(0, LLMMessage(role="system", content=self.config.system_prompt))
        self._consumed_tool_results = 0
        self._consumed_feedback: set[str] = set()
        self._finalization_nudged = False
        self._terminal_json_fallback_requested = False

    async def __call__(self, task, context: dict[str, Any]) -> dict[str, Any]:
        self._append_context_messages(task, context)
        terminal_schemas = self._terminal_schemas()
        force_terminal = self._should_force_terminal(task, context) and bool(terminal_schemas)
        terminal_attempted = self._finalization_nudged
        if force_terminal and not self._finalization_nudged:
            terminal_name = terminal_schemas[0]["function"]["name"]
            self.messages.append(LLMMessage(
                role="user",
                content=(
                    "Evidence collection budget is complete. Reconcile the collected evidence now and "
                    f"call {terminal_name}. Do not call another evidence tool. Preserve explicit gaps."
                ),
            ))
            self._finalization_nudged = True
        use_terminal_json_fallback = bool(
            force_terminal
            and self.config.allow_terminal_json_fallback
            and (
                self._prefers_structured_terminal_json()
                or terminal_attempted
            )
        )
        if use_terminal_json_fallback:
            terminal_name = terminal_schemas[0]["function"]["name"]
            parameters = terminal_schemas[0].get("function", {}).get("parameters", {})
            required_fields = [
                str(field) for field in parameters.get("required", [])
                if str(field).strip()
            ]
            optional_fields = [
                str(field) for field in parameters.get("properties", {})
                if str(field).strip() and str(field) not in required_fields
            ]
            self.messages.append(LLMMessage(
                role="user",
                content=(
                    "Do not call tools. Return exactly one JSON object with no markdown. "
                    f"Its top-level fields must be terminal_action={json.dumps(terminal_name)} and output. "
                    "output must contain actual finding values, not a JSON Schema. "
                    f"Required output fields: {', '.join(required_fields) or 'none'}. "
                    + (
                        f"Optional output fields: {', '.join(optional_fields)}. "
                        if optional_fields else ""
                    )
                    + "Do not include schema keywords such as type, properties, or required. "
                    "Preserve the candidate identity and explicitly record any unresolved evidence gaps."
                ),
            ))
            self._terminal_json_fallback_requested = True
        self.messages = self.context_window.compact(self.messages)
        available_schemas = (
            [] if use_terminal_json_fallback
            else terminal_schemas if force_terminal
            else self.tool_schemas
        )
        provider_options: dict[str, Any] = {}
        if available_schemas:
            provider_options["parallel_tool_calls"] = False
        # DeepSeek's OpenAI-compatible endpoint accepts tool definitions but
        # rejects the OpenAI-specific named-function form of ``tool_choice``.
        # A forced-terminal turn exposes only the terminal schema, so omitting
        # that unsupported hint retains the same capability boundary.
        if force_terminal and not use_terminal_json_fallback and self._supports_named_tool_choice():
            provider_options["tool_choice"] = {
                "type": "function",
                "function": {"name": terminal_schemas[0]["function"]["name"]},
            }
        response = await self.llm_service.chat(
            self.messages,
            model=self.config.model,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            tools=available_schemas or None,
            **provider_options,
        )
        content = self._response_value(response, "content", "") or ""
        tool_calls = self._response_value(response, "tool_calls", None) or []
        usage = self._response_value(response, "usage", {}) or {}
        tokens = int(usage.get("total_tokens", 0) or 0)
        normalized_tool_calls = [
            self._normalize_tool_call(tool_call)
            for tool_call in tool_calls
        ]
        selected_call = normalized_tool_calls[0] if normalized_tool_calls else None
        is_terminal_call = bool(
            selected_call and selected_call["name"] in set(self.config.terminal_tools)
        )
        # Keep every non-terminal call in the transcript. Some OpenAI-compatible
        # providers return a batch even when parallel_tool_calls is false, and
        # reject the next request unless every call in that batch has a result.
        # The task loop executes that batch serially under the usual tool policy.
        # Terminal actions are consumed locally by the harness and therefore do
        # not receive a provider tool result; they must not remain unpaired.
        transcript_tool_calls = [] if is_terminal_call else list(tool_calls)
        self.messages.append(
            LLMMessage(
                role="assistant",
                content=str(content),
                tool_calls=transcript_tool_calls or None,
            )
        )

        if tool_calls:
            call = selected_call
            if is_terminal_call:
                return {
                    "done": True,
                    "output": call["arguments"],
                    "tokens_used": tokens,
                    "reason": "terminal tool requested",
                    "terminal_action": call["name"],
                }
            return {
                "status": "needs_tool",
                "tool_call": call,
                "tool_calls": normalized_tool_calls,
                "output": {"assistant_message": str(content)},
                "tokens_used": tokens,
            }

        parsed = self._parse_json(content)
        if use_terminal_json_fallback and isinstance(parsed, dict):
            terminal_name = terminal_schemas[0]["function"]["name"]
            output = parsed.get("output")
            if parsed.get("terminal_action") == terminal_name and isinstance(output, dict):
                return {
                    "done": True,
                    "output": output,
                    "tokens_used": tokens,
                    "reason": "structured terminal JSON fallback",
                    "terminal_action": terminal_name,
                }
        if isinstance(parsed, dict) and parsed.get("done") is True:
            return {
                "done": True,
                "output": dict(parsed.get("output", parsed)),
                "tokens_used": tokens,
                "reason": "structured terminal response",
            }
        return {
            "done": False,
            "output": {"assistant_message": str(content)},
            "tokens_used": tokens,
            "reason": "model requested another turn",
        }

    def _terminal_schemas(self) -> list[dict[str, Any]]:
        terminal_names = set(self.config.terminal_tools)
        return [
            schema for schema in self.tool_schemas
            if str(schema.get("function", {}).get("name", "")) in terminal_names
        ]

    def _supports_named_tool_choice(self) -> bool:
        """Return whether this provider accepts OpenAI's named tool-choice form."""
        provider = str(getattr(self.llm_service, "provider", "")).strip().lower()
        return provider != "deepseek"

    def _prefers_structured_terminal_json(self) -> bool:
        """DeepSeek accepts JSON finals reliably but rejects forced function choice."""
        provider = str(getattr(self.llm_service, "provider", "")).strip().lower()
        return provider == "deepseek"

    def _should_force_terminal(self, task, context: dict[str, Any]) -> bool:
        tool_result_count = len(list(context.get("tool_results", [])))
        minimum = max(0, int(self.config.minimum_tool_results_before_terminal))
        if tool_result_count < minimum:
            return False
        result_limit = max(0, int(self.config.force_terminal_after_tool_results))
        turn_limit = max(0, int(self.config.force_terminal_after_turn))
        return bool(
            (result_limit and tool_result_count >= result_limit)
            or (turn_limit and int(getattr(task, "turn_count", 0)) >= turn_limit)
        )

    def _append_context_messages(self, task, context: dict[str, Any]) -> None:
        for key in (
            "guard_feedback",
            "completion_feedback",
            "loop_feedback",
            "terminal_action_feedback",
        ):
            value = str(context.get(key, "")).strip()
            if value and value not in self._consumed_feedback:
                self.messages.append(LLMMessage(role="user", content=f"Runtime feedback: {value}"))
                self._consumed_feedback.add(value)

        results = list(context.get("tool_results", []))
        while self._consumed_tool_results < len(results):
            item = results[self._consumed_tool_results]
            self._consumed_tool_results += 1
            tool_name = str(item.get("tool", "tool")) if isinstance(item, dict) else "tool"
            tool_call_id = item.get("tool_call_id") if isinstance(item, dict) else None
            payload = item.get("output", item) if isinstance(item, dict) else item
            self.messages.append(
                LLMMessage(
                    role="tool",
                    name=tool_name,
                    content=json.dumps(payload, default=str),
                    tool_call_id=tool_call_id,
                )
            )

    @staticmethod
    def _response_value(response: Any, key: str, default: Any) -> Any:
        if isinstance(response, dict):
            return response.get(key, default)
        return getattr(response, key, default)

    @staticmethod
    def _normalize_tool_call(raw: dict[str, Any]) -> dict[str, Any]:
        function = raw.get("function", raw)
        name = str(function.get("name", raw.get("name", "")))
        call_id = raw.get("id") or function.get("id")
        arguments = function.get("arguments", function.get("input", raw.get("arguments", {})))
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {"raw_arguments": arguments}
        return {"id": call_id, "name": name, "arguments": dict(arguments or {})}

    @staticmethod
    def _parse_json(content: str) -> dict[str, Any] | None:
        text = str(content or "").strip()
        if text.startswith("```"):
            text = text.strip("`").split("\n", 1)[-1].strip()
        try:
            value = json.loads(text)
        except (TypeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def to_state(self) -> dict[str, Any]:
        return {
            "messages": [message.to_dict() for message in self.messages],
            "consumed_tool_results": self._consumed_tool_results,
            "consumed_feedback": sorted(self._consumed_feedback),
            "finalization_nudged": self._finalization_nudged,
            "terminal_json_fallback_requested": self._terminal_json_fallback_requested,
            "context_window": self.context_window.to_dict(),
        }

    def restore_state(self, data: dict[str, Any]) -> None:
        self.messages = [
            LLMMessage(
                role=str(item.get("role", "user")),
                content=str(item.get("content", "")),
                name=item.get("name"),
                tool_calls=item.get("tool_calls"),
                tool_call_id=item.get("tool_call_id"),
            )
            for item in data.get("messages", [])
        ]
        self._consumed_tool_results = int(data.get("consumed_tool_results", 0))
        self._consumed_feedback = set(data.get("consumed_feedback", []))
        self._finalization_nudged = bool(data.get("finalization_nudged", False))
        self._terminal_json_fallback_requested = bool(data.get("terminal_json_fallback_requested", False))
        self.context_window = ContextWindow.from_dict(data.get("context_window", {}))
