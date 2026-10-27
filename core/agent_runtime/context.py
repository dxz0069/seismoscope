"""Bounded transcript state and lightweight context compaction."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List
from collections.abc import Iterable

from ..llm_service import LLMMessage


@dataclass
class ContextWindow:
    max_messages: int = 80
    max_chars: int = 120_000
    compacted_count: int = 0
    compaction_events: list[dict[str, Any]] = field(default_factory=list)

    def compact(self, messages: Iterable[LLMMessage]) -> list[LLMMessage]:
        items = list(messages)
        if not items:
            return items
        total_chars = sum(len(str(item.content or "")) for item in items)
        if len(items) <= self.max_messages and total_chars <= self.max_chars:
            return items

        system = [item for item in items if item.role == "system"][:1]
        non_system = [item for item in items if item.role != "system"]
        blocks = self._protocol_blocks(non_system)
        message_budget = max(1, self.max_messages - len(system) - 1)
        kept_blocks: list[list[LLMMessage]] = []
        kept_count = 0
        for block in reversed(blocks):
            if kept_blocks and kept_count + len(block) > message_budget:
                continue
            if len(block) > message_budget:
                continue
            kept_blocks.insert(0, block)
            kept_count += len(block)
            if kept_count >= message_budget:
                break
        if not kept_blocks and blocks:
            kept_blocks = [self._make_protocol_safe(blocks[-1])]
        tail = [message for block in kept_blocks for message in block]
        dropped = max(0, len(non_system) - len(tail))
        summary = LLMMessage(
            role="system",
            name="context_compaction",
            content=(
                f"Prior transcript compacted. {dropped} messages were summarized and removed. "
                "Preserve confirmed evidence, unresolved gaps, and the next required action."
            ),
        )
        result = system + [summary] + tail
        while self._char_count(result) > self.max_chars and len(kept_blocks) > 1:
            kept_blocks.pop(0)
            tail = [message for block in kept_blocks for message in block]
            result = system + [summary] + tail
        if self._char_count(result) > self.max_chars:
            result = self._truncate_contents(result)
        self.compacted_count += 1
        self.compaction_events.append({
            "dropped_messages": dropped,
            "remaining_messages": len(result),
            "protocol_safe": self._is_protocol_safe(result),
        })
        return result

    @staticmethod
    def _protocol_blocks(messages: list[LLMMessage]) -> list[list[LLMMessage]]:
        blocks: list[list[LLMMessage]] = []
        index = 0
        while index < len(messages):
            message = messages[index]
            if message.role == "tool":
                index += 1
                continue
            if message.role != "assistant" or not message.tool_calls:
                blocks.append([message])
                index += 1
                continue

            expected = {str(call.get("id")) for call in message.tool_calls if call.get("id")}
            block = [message]
            found = set()
            cursor = index + 1
            while cursor < len(messages) and messages[cursor].role == "tool":
                tool_message = messages[cursor]
                block.append(tool_message)
                if tool_message.tool_call_id:
                    found.add(str(tool_message.tool_call_id))
                cursor += 1
            blocks.append(block if expected and expected.issubset(found) else [
                LLMMessage(role="assistant", content=message.content, name=message.name)
            ])
            index = cursor
        return blocks

    @staticmethod
    def _make_protocol_safe(block: list[LLMMessage]) -> list[LLMMessage]:
        if block and block[0].role == "assistant" and block[0].tool_calls:
            expected = {str(call.get("id")) for call in block[0].tool_calls if call.get("id")}
            found = {str(item.tool_call_id) for item in block[1:] if item.tool_call_id}
            if not expected or not expected.issubset(found):
                return [LLMMessage(role="assistant", content=block[0].content, name=block[0].name)]
        return block

    @staticmethod
    def _is_protocol_safe(messages: list[LLMMessage]) -> bool:
        for index, message in enumerate(messages):
            if message.role == "tool":
                if index == 0 or messages[index - 1].role not in {"assistant", "tool"}:
                    return False
            if message.role == "assistant" and message.tool_calls:
                expected = {str(call.get("id")) for call in message.tool_calls if call.get("id")}
                found = set()
                cursor = index + 1
                while cursor < len(messages) and messages[cursor].role == "tool":
                    if messages[cursor].tool_call_id:
                        found.add(str(messages[cursor].tool_call_id))
                    cursor += 1
                if not expected or not expected.issubset(found):
                    return False
        return True

    def _truncate_contents(self, messages: list[LLMMessage]) -> list[LLMMessage]:
        per_message = max(16, self.max_chars // max(1, len(messages)))
        truncated = []
        for message in messages:
            content = str(message.content or "")
            if len(content) > per_message:
                content = content[:max(0, per_message - 12)] + "...[compact]"
            truncated.append(LLMMessage(
                role=message.role,
                content=content,
                name=message.name,
                tool_calls=message.tool_calls,
                tool_call_id=message.tool_call_id,
            ))
        return truncated

    @staticmethod
    def _char_count(messages: list[LLMMessage]) -> int:
        return sum(len(str(item.content or "")) for item in messages)

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_messages": self.max_messages,
            "max_chars": self.max_chars,
            "compacted_count": self.compacted_count,
            "compaction_events": self.compaction_events,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContextWindow:
        return cls(
            max_messages=int(data.get("max_messages", 80)),
            max_chars=int(data.get("max_chars", 120_000)),
            compacted_count=int(data.get("compacted_count", 0)),
            compaction_events=list(data.get("compaction_events", [])),
        )
