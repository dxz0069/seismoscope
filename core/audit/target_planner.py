"""Deterministic planning of bounded Agent source-audit targets."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..tool_fabric.dependency_inspection import is_dependency_file
from ..tool_fabric.source_tools import IGNORED_DIRECTORIES, SOURCE_EXTENSIONS


LANE_NODE_TYPES = {
    "web_audit": {"entry_point", "code_block", "trust_boundary", "permission"},
    "agent_audit": {"prompt", "tool", "permission", "privileged_asset", "code_block"},
    "mcp_audit": {"tool", "prompt", "trust_boundary", "permission", "privileged_asset"},
    "secrets_audit": {"code_block", "privileged_asset"},
    "workflow_audit": {"entry_point", "tool", "trust_boundary", "privileged_asset", "code_block"},
}

LANE_TECHNIQUES = {
    "web_audit": {"T-UNPROTECTED-ENTRY"},
    "agent_audit": {"T-PROMPT-INJECTION", "T-EXCESSIVE-AGENCY"},
    "mcp_audit": {"T-MCP-DESCRIPTION-INJECTION", "T-EXCESSIVE-AGENCY"},
    "secrets_audit": set(),
    "workflow_audit": {"T-UNPROTECTED-ENTRY", "T-EXCESSIVE-AGENCY"},
}


@dataclass
class AuditTarget:
    target_id: str
    lane: str
    objective: str
    seed_files: List[str] = field(default_factory=list)
    hypothesis_ids: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    priority: int = 50
    expected_tool_calls: int = 6

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AuditTargetPlanner:
    def __init__(self, project_path: str):
        self.project_root = Path(project_path).resolve()

    def plan(
        self,
        *,
        lane: str,
        candidates: Optional[Iterable[Dict[str, Any]]] = None,
        surface_graph: Optional[Dict[str, Any]] = None,
        threat_model: Optional[Dict[str, Any]] = None,
        changed_files: Optional[Iterable[str]] = None,
        max_targets: int = 3,
        files_per_target: int = 8,
    ) -> List[AuditTarget]:
        max_targets = max(1, min(12, int(max_targets)))
        files_per_target = max(1, min(30, int(files_per_target)))
        candidates = list(candidates or [])
        graph = dict(surface_graph or {})
        threat_model = dict(threat_model or {})

        candidate_files = _unique(
            _valid_relative(item.get("file_path")) for item in candidates
            if item.get("file_path")
        )
        relevant_types = LANE_NODE_TYPES.get(lane, LANE_NODE_TYPES["web_audit"])
        graph_files = _unique(
            _valid_relative((node.get("attributes") or {}).get("file_path"))
            for node in graph.get("nodes", [])
            if node.get("type") in relevant_types
        )
        technique_ids = LANE_TECHNIQUES.get(lane, set())
        hypotheses = [
            item for item in threat_model.get("hypotheses", [])
            if not technique_ids or item.get("technique_id") in technique_ids
        ]
        hypothesis_ids = [str(item.get("id")) for item in hypotheses if item.get("id")]
        discovered_files = self.source_inventory(limit=max_targets * files_per_target * 3)
        inventory_set = set(discovered_files)
        changed_files = _unique(
            _valid_relative(item) for item in (changed_files or [])
            if _valid_relative(item) in inventory_set
        )

        groups: List[tuple[str, List[str], List[str], List[str], int]] = []
        if changed_files:
            groups.append((
                "Audit changed files first, then trace their callers, callees, guards, configuration, and impact sinks.",
                changed_files,
                hypothesis_ids,
                ["changed_file_scope", "transitive_security_context"],
                110,
            ))
        if candidate_files:
            groups.append((
                "Trace deterministic security signals through callers, guards, and impact sinks.",
                candidate_files,
                hypothesis_ids,
                ["deterministic_candidates"],
                100,
            ))
        if graph_files or hypothesis_ids:
            groups.append((
                "Investigate runtime-surface trust boundaries and test the selected risk hypotheses against source.",
                graph_files,
                hypothesis_ids,
                ["runtime_surface", "threat_hypotheses"],
                80,
            ))
        covered = set(changed_files) | set(candidate_files) | set(graph_files)
        fallback = [item for item in discovered_files if item not in covered]
        if fallback or not groups:
            groups.append((
                "Explore uncovered entry points, sensitive operations, and cross-file data flows for this audit lane.",
                fallback or discovered_files,
                [],
                ["source_coverage"],
                50,
            ))

        targets: List[AuditTarget] = []
        for objective, files, target_hypotheses, reasons, priority in groups:
            chunks = list(_chunks(files, files_per_target)) or [[]]
            for chunk in chunks:
                identity = "|".join([lane, objective, *chunk, *target_hypotheses])
                target_id = "target-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
                targets.append(AuditTarget(
                    target_id=target_id,
                    lane=lane,
                    objective=objective,
                    seed_files=chunk,
                    hypothesis_ids=target_hypotheses[:20],
                    reasons=reasons,
                    priority=priority,
                    expected_tool_calls=max(4, min(12, len(chunk) + 3)),
                ))
        targets.sort(key=lambda item: (-item.priority, item.target_id))
        return targets[:max_targets]

    def source_inventory(self, *, limit: int = 100_000) -> List[str]:
        """Return a deterministic bounded inventory for coverage accounting."""
        files = []
        for path in self.project_root.rglob("*"):
            if not path.is_file() or (
                path.suffix.lower() not in SOURCE_EXTENSIONS and not is_dependency_file(path)
            ):
                continue
            if any(part in IGNORED_DIRECTORIES for part in path.relative_to(self.project_root).parts):
                continue
            files.append(path.relative_to(self.project_root).as_posix())
            if len(files) >= limit:
                break
        return sorted(files)


def _valid_relative(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip().lstrip("/")
    return "" if not text or text.startswith("../") or "/../" in text else text


def _unique(values: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(value for value in values if value))


def _chunks(values: List[str], size: int):
    for index in range(0, len(values), size):
        yield values[index:index + size]
