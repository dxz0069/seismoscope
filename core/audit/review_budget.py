"""Shared, in-memory limits for bounded LLM candidate review."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Iterable, Set


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
        self._registrations: Dict[str, list[Dict[str, Any]]] = {}
        self._selected_by_lane: Dict[str, Set[str]] = {}
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
        candidates: Iterable[Dict[str, Any]],
    ) -> Set[str]:
        """Wait for every lane, then select the globally highest-risk candidates."""
        if not self.uses_global_selection:
            return set()

        normalized = [
            {
                "id": str(candidate.get("id", "")),
                "severity": str(candidate.get("severity", "medium")).lower(),
                "confidence": float(candidate.get("confidence", 0.0) or 0.0),
                "order": int(candidate.get("order", 0) or 0),
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

    def _finalize_selection(self) -> None:
        if self._selection_finalized:
            return
        ranked = []
        for lane, candidates in self._registrations.items():
            for candidate in candidates:
                ranked.append((
                    self._SEVERITY_RANK.get(candidate["severity"], 5),
                    -candidate["confidence"],
                    lane,
                    candidate["order"],
                    candidate["id"],
                ))
        ranked.sort()
        selected = ranked[:self.limit]
        self._selected_by_lane = {}
        for _, _, lane, _, candidate_id in selected:
            self._selected_by_lane.setdefault(lane, set()).add(candidate_id)
        self._claimed = len(selected)
        self._remaining = self.limit - self._claimed
        self._selection_finalized = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "limit": self.limit,
            "claimed": self._claimed,
            "remaining": self._remaining,
            "selection_mode": "global_priority" if self.uses_global_selection else "atomic_claim",
            "registered_lanes": len(self._registrations),
            "expected_lanes": self.expected_lanes,
        }
