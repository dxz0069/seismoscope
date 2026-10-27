"""Finding 级误报抑制：本地抑制库 + 合并阶段过滤。

抑制只来自工具侧本地存储（``<state_root>/suppressions/<项目哈希>.json``），
永不来自被审计源码内容；匹配维度为 漏洞类型 + 文件路径（可选行号 ±5），
命中即在合并阶段移除并随结果回显，保持可审计。
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any


def _state_root() -> Path:
    return Path(os.getenv("VIBE_SEC_STATE_HOME", str(Path.home() / ".vibe-sec"))).resolve()


def suppression_store_path(project_path: str) -> Path:
    key = hashlib.sha256(str(Path(project_path).resolve()).encode("utf-8")).hexdigest()[:16]
    return _state_root() / "suppressions" / f"{key}.json"


def load_suppressions(project_path: str) -> list[dict[str, Any]]:
    path = suppression_store_path(project_path)
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return []
    entries = payload.get("entries", []) if isinstance(payload, dict) else []
    return [entry for entry in entries if isinstance(entry, dict)]


def add_suppression(
    project_path: str,
    *,
    vulnerability_type: str,
    file_path: str,
    line: int | None = None,
    reason: str = "",
) -> dict[str, Any]:
    entry = {
        "id": f"sup-{hashlib.sha256(f'{vulnerability_type}|{file_path}|{line}'.encode()).hexdigest()[:12]}",
        "vulnerability_type": vulnerability_type,
        "file_path": str(file_path).replace("\\", "/"),
        "line": int(line) if line else None,
        "reason": reason,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    path = suppression_store_path(project_path)
    entries = [e for e in load_suppressions(project_path) if e.get("id") != entry["id"]]
    entries.append(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"schema": "vibe-sec.suppressions.v1", "entries": entries}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return entry


def match_suppression(finding: dict[str, Any], entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    rel = str(finding.get("file_path", "")).replace("\\", "/")
    for entry in entries:
        if entry.get("vulnerability_type") and entry.get("vulnerability_type") != finding.get("vulnerability_type"):
            continue
        target = str(entry.get("file_path", "")).replace("\\", "/")
        if target and not (rel == target or rel.endswith("/" + target) or rel.endswith(target)):
            continue
        line = entry.get("line")
        if line and abs(int(finding.get("line_start", 0) or 0) - int(line)) > 5:
            continue
        return entry
    return None


def apply_suppressions(
    findings: list[dict[str, Any]], project_path: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """按本地抑制库过滤 finding，返回 (保留列表, 命中列表含抑制条目)。"""
    entries = load_suppressions(project_path)
    if not entries:
        return findings, []
    kept: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for finding in findings:
        entry = match_suppression(finding, entries)
        if entry is None:
            kept.append(finding)
        else:
            suppressed.append({"finding": finding, "suppression": entry})
    return kept, suppressed
