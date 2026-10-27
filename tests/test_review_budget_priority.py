"""LLM 审查预算的定向优先级：安全控制例程加权、测试目录降权。"""

from __future__ import annotations

import asyncio

from core.audit.review_budget import SharedReviewBudget


def _candidate(cid: str, severity: str, confidence: float, path: str, evidence: str = "") -> dict:
    return {
        "id": cid, "severity": severity, "confidence": confidence,
        "order": 0, "file_path": path, "evidence_text": evidence,
    }


def test_security_control_candidates_outrank_equal_severity():
    budget = SharedReviewBudget(limit=1, expected_lanes=2)

    async def run() -> None:
        await asyncio.gather(
            budget.select_for_lane("web", [
                _candidate("plain", "high", 0.8, "src/routes/books.py"),
                _candidate("escape", "high", 0.5, "src/util/escape_html.js"),
                _candidate("test-noise", "high", 0.9, "test/unit/serialize.js"),
            ]),
            budget.select_for_lane("other", []),
        )

    asyncio.run(run())
    assert budget._selected_by_lane == {"web": {"escape"}}


def test_test_dir_candidates_rank_last():
    budget = SharedReviewBudget(limit=2, expected_lanes=2)

    async def run() -> None:
        await asyncio.gather(
            budget.select_for_lane("web", [
                _candidate("t1", "high", 0.9, "test/unit/serialize.js"),
                _candidate("t2", "high", 0.9, "tests/api.test.js"),
                _candidate("src", "high", 0.5, "src/service.py"),
            ]),
            budget.select_for_lane("other", []),
        )

    asyncio.run(run())
    assert budget._selected_by_lane == {"web": {"src", "t1"}}, "限额内先取 src，剩余给测试目录"


def test_evidence_markers_also_boost():
    budget = SharedReviewBudget(limit=1, expected_lanes=2)

    async def run() -> None:
        await asyncio.gather(
            budget.select_for_lane("secrets", [
                _candidate("a", "medium", 0.9, "src/misc.py"),
                _candidate("b", "medium", 0.3, "src/misc.py", "calls sanitizeInput()"),
            ]),
            budget.select_for_lane("other", []),
        )

    asyncio.run(run())
    assert budget._selected_by_lane == {"secrets": {"b"}}


def test_severity_still_dominates_priority():
    budget = SharedReviewBudget(limit=1, expected_lanes=2)

    async def run() -> None:
        await asyncio.gather(
            budget.select_for_lane("web", [
                _candidate("ctrl", "medium", 0.9, "src/escape.js"),
                _candidate("crit", "critical", 0.1, "src/plain.py"),
            ]),
            budget.select_for_lane("other", []),
        )

    asyncio.run(run())
    assert budget._selected_by_lane == {"web": {"crit"}}, "严重级排序先于定向优先级"
