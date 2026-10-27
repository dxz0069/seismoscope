"""Shared, in-memory limits for bounded LLM candidate review."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any


class SharedReviewBudget:
    """Atomically allocate a finite number of reviews across audit lanes."""

    _SEVERITY_RANK = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    def __init__(self, limit: int, *, expected_lanes: int = 0):
        self.limit = max(0, int(limit))
        self.expected_lanes = max(0, int(expected_lanes))
        self._remaining = self.limit
        self._claimed = 0
        self._lock = asyncio.Lock()
        self._selection_condition = asyncio.Condition()
        self._registrations: dict[str, list[dict[str, Any]]] = {}
        self._selected_by_lane: dict[str, set[str]] = {}
        self._selection_finalized = False

    @property
    def uses_global_selection(self) -> bool:
        return self.expected_lanes > 1

    async def claim(self) -> bool:
        async with self._lock:
            if self._remaining <= 0:
                return False
            self._remaining -= 1
            self._claimed += 1
            return True

    async def select_for_lane(
        self,
        lane: str,
        candidates: Iterable[dict[str, Any]],
    ) -> set[str]:
        """Wait for every lane, then select the globally highest-risk candidates."""
        if not self.uses_global_selection:
            return set()

        normalized = [
            {
                "id": str(candidate.get("id", "")),
                "severity": str(candidate.get("severity", "medium")).lower(),
                "confidence": float(candidate.get("confidence", 0.0) or 0.0),
                "order": int(candidate.get("order", 0) or 0),
                "file_path": str(candidate.get("file_path", "")),
                "evidence": str(candidate.get("evidence_text", "")),
            }
            for candidate in candidates
            if str(candidate.get("id", ""))
        ]
        async with self._selection_condition:
            self._registrations[str(lane)] = normalized
            if len(self._registrations) >= self.expected_lanes:
                self._finalize_selection()
                self._selection_condition.notify_all()
            else:
                await self._selection_condition.wait_for(lambda: self._selection_finalized)
            return set(self._selected_by_lane.get(str(lane), set()))

    @staticmethod
    def _targeted_priority(candidate: dict[str, Any]) -> int:
        """LLM 预算的定向优先级（越小越优先）。

        - 安全控制例程（escape/sanitize/neutralize/encode/validate/deserialize
          所在文件或证据）加权提前：这是 "false positivity" 高发位——看着已
          加固实则可绕过，LLM 深读其实现的边际价值最高（实测：serialize-
          javascript 语义绕过曾因审查预算未抵达此处而漏检）。
        - 测试目录候选降权最后：审查预算大量耗在 test 文件是首测中
          "45 个发现全落测试、sink 零命中"的直接原因。
        """
        path = (candidate.get("file_path") or "").lower()
        evidence = (candidate.get("evidence") or "").lower()
        control_markers = (
            "escape", "sanitize", "sanitise", "neutralize", "neutralise",
            "encode", "validate", "deserialize", "unserialize", "purify", "filter",
        )
        if any(marker in path or marker in evidence for marker in control_markers):
            return 0
        if any(part in path for part in ("/test", "test/", "/tests", "tests/", "/__tests__", ".spec.", ".test.")):
            return 2
        return 1

    def _finalize_selection(self) -> None:
        if self._selection_finalized:
            return
        ranked = []
        for lane, candidates in self._registrations.items():
            for candidate in candidates:
                ranked.append((
                    self._SEVERITY_RANK.get(candidate["severity"], 5),
                    self._targeted_priority(candidate),
                    -candidate["confidence"],
                    lane,
                    candidate["order"],
                    candidate["id"],
                ))
        ranked.sort()
        selected = ranked[:self.limit]
        self._selected_by_lane = {}
        for _, _, _, lane, _, candidate_id in selected:
            self._selected_by_lane.setdefault(lane, set()).add(candidate_id)
        self._claimed = len(selected)
        self._remaining = self.limit - self._claimed
        self._selection_finalized = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "limit": self.limit,
            "claimed": self._claimed,
            "remaining": self._remaining,
            "selection_mode": "global_priority" if self.uses_global_selection else "atomic_claim",
            "registered_lanes": len(self._registrations),
            "expected_lanes": self.expected_lanes,
        }
