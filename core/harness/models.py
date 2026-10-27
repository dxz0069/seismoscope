"""Runtime graph and project profile contracts."""

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from hashlib import sha1, sha256
from typing import Any

from .vrtm import EvidenceLevel, enrich_runtime_graph


def stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(part or "") for part in parts)
    return f"{prefix}-{sha1(raw.encode('utf-8')).hexdigest()[:12]}"


def _edge_identity(edge: "RuntimeSurfaceEdge") -> str:
    return stable_id("edge", edge.source, edge.target, edge.relation)


_OVERVIEW_ROLE_BY_NODE_TYPE = {
    "external_actor": "external_input",
    "human_operator": "external_input",
    "service_identity": "external_input",
    "external_content": "external_input",
    "external_service": "external_input",
    "entry_point": "application_entry",
    "workflow": "agent_workflow",
    "coding_agent": "agent_workflow",
    "runtime_agent": "agent_workflow",
    "prompt": "ai_context",
    "model": "ai_context",
    "memory": "ai_context",
    "retriever": "ai_context",
    "tool": "capability",
    "mcp_capability": "capability",
    "code_execution": "capability",
    "deployment_capability": "capability",
    "trust_boundary": "control_boundary",
    "permission": "control_boundary",
    "security_control": "control_boundary",
    "approval_control": "control_boundary",
    "policy_gateway": "control_boundary",
    "browser_sink": "sensitive_asset",
    "storage_asset": "sensitive_asset",
    "privileged_asset": "sensitive_asset",
    "secret_asset": "sensitive_asset",
    "source_artifact": "sensitive_asset",
    "deployment_asset": "sensitive_asset",
}

_OVERVIEW_ROLE_META = {
    "external_input": ("外部与不可信输入", 0, "source", "#b42318"),
    "application_entry": ("应用入口", 1, "entry", "#d97706"),
    "ai_context": ("智能上下文（提示词、模型、记忆）", 2, "context", "#7c3aed"),
    "agent_workflow": ("自动化代理与工作流", 2, "context", "#4f46e5"),
    "capability": ("可调用能力（工具、MCP、执行）", 3, "capability", "#2563eb"),
    "control_boundary": ("信任边界、授权与审批", 3, "control", "#15803d"),
    "sensitive_asset": ("敏感资产与输出", 4, "asset", "#9f1239"),
}

_EVIDENCE_RANK = {
    "unknown": 0,
    "inferred": 1,
    "declared": 2,
    "static_observed": 3,
    "runtime_observed": 4,
    "verified": 5,
}

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_TERMINAL_RISK_STATUSES = {"refuted", "mitigated", "resolved"}


def _projection_evidence(items: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Describe an aggregation without promoting member evidence to runtime proof."""
    values = [dict(item or {}) for item in items]
    levels = [str(item.get("level", "unknown")) for item in values]
    strongest = max(levels or ["unknown"], key=lambda level: _EVIDENCE_RANK.get(level, 0))
    confidence_values = [float(item.get("confidence", 0) or 0) for item in values]
    return {
        "level": "static_observed" if strongest != "unknown" else "unknown",
        "confidence": round(max(confidence_values, default=0.0), 3),
        "source": "semantic_runtime_projection",
        "member_evidence_levels": sorted(set(levels)),
        "note": "Aggregated from source-grounded entities; inspect source trace for member evidence.",
    }


def _ordered_risk_ids(risk_paths: Iterable[dict[str, Any]], limit: int = 8) -> list[str]:
    """Return the most severe paths that still require a security decision.

    A refuted or mitigated hypothesis remains in the model as audit history, but
    highlighting it in the default overview makes a resolved path look like an
    active alert.  The source trace can still show its evidence on demand.
    """
    ranked = sorted(
        (
            dict(item)
            for item in risk_paths
            if str(item.get("status", "open")).lower() not in _TERMINAL_RISK_STATUSES
        ),
        key=lambda item: (
            -_SEVERITY_RANK.get(str(item.get("severity", "")).lower(), 0),
            -float(item.get("confidence", 0) or 0),
            str(item.get("technique_id", "")),
            str(item.get("id", "")),
        ),
    )
    return [str(item.get("id")) for item in ranked[:limit] if item.get("id")]


def _semantic_runtime_projection(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    risk_paths: list[dict[str, Any]],
    *,
    view_id: str,
    title: str,
    flow_planes: set[str] | None = None,
) -> dict[str, Any]:
    """Collapse implementation detail into a small, decision-oriented runtime view.

    The raw graph remains intact for source tracing.  This projection intentionally
    treats code blocks as connecting evidence, not as decision nodes.
    """
    nodes_by_id = {str(node["id"]): node for node in nodes if node.get("id")}
    role_by_node_id = {
        node_id: _OVERVIEW_ROLE_BY_NODE_TYPE.get(str(node.get("type", "")))
        for node_id, node in nodes_by_id.items()
    }
    selected_risk_ids = set(_ordered_risk_ids(risk_paths))
    path_by_id = {str(path.get("id")): path for path in risk_paths if path.get("id")}

    def is_visible_edge(edge: dict[str, Any]) -> bool:
        return not flow_planes or bool(set(edge.get("flow_planes", []) or []) & flow_planes)

    visible_edges = [edge for edge in edges if is_visible_edge(edge)]
    outgoing: dict[str, list[dict[str, Any]]] = {}
    for edge in visible_edges:
        outgoing.setdefault(str(edge.get("source", "")), []).append(edge)

    category_members: dict[str, list[dict[str, Any]]] = {}
    for node_id, node in nodes_by_id.items():
        role = role_by_node_id.get(node_id)
        if role:
            category_members.setdefault(role, []).append(node)

    # Risk paths provide the authoritative visual emphasis even where extracted
    # implementation edges have been compressed away.
    path_role_ids: dict[str, list[str]] = {}
    edge_risk_ids: dict[tuple[str, str], set[str]] = {}
    for path_id, path in path_by_id.items():
        if flow_planes and not (set(path.get("flow_planes", []) or []) & flow_planes):
            continue
        role_ids: list[str] = []
        for node_id in path.get("path_node_ids", []) or []:
            role = role_by_node_id.get(str(node_id))
            if role:
                semantic_id = f"{view_id}:{role}"
                if not role_ids or role_ids[-1] != semantic_id:
                    role_ids.append(semantic_id)
        path_role_ids[path_id] = role_ids
        for source, target in zip(role_ids, role_ids[1:], strict=False):
            edge_risk_ids.setdefault((source, target), set()).add(path_id)

    projected_edges: dict[tuple[str, str], dict[str, Any]] = {}

    def add_projected_edge(
        source_role: str,
        target_role: str,
        *,
        source_edge: dict[str, Any] | None = None,
        risk_ids: Iterable[str] | None = None,
    ) -> None:
        if source_role == target_role:
            return
        source_id = f"{view_id}:{source_role}"
        target_id = f"{view_id}:{target_role}"
        key = (source_id, target_id)
        value = projected_edges.setdefault(key, {
            "id": stable_id("projection-edge", view_id, source_role, target_role),
            "source": source_id,
            "target": target_id,
            "relation": "semantic_flow",
            "semantic_relation": "semantic_flow",
            "flow_planes": set(),
            "evidence_items": [],
            "relations": set(),
            "represented_edge_ids": set(),
            "risk_hypothesis_ids": set(),
        })
        if source_edge:
            value["flow_planes"].update(source_edge.get("flow_planes", []) or [])
            value["evidence_items"].append(source_edge.get("evidence", {}))
            value["relations"].add(str(source_edge.get("semantic_relation") or source_edge.get("relation") or "flows"))
            if source_edge.get("id"):
                value["represented_edge_ids"].add(str(source_edge["id"]))
            value["risk_hypothesis_ids"].update(source_edge.get("risk_hypothesis_ids", []) or [])
        value["risk_hypothesis_ids"].update(risk_ids or [])

    # Contract only code-block chains. Traversal stops at the next meaningful
    # runtime role, preserving direction and preventing arbitrary graph closure.
    for source_id, source_role in role_by_node_id.items():
        if not source_role:
            continue
        queue = list(outgoing.get(source_id, []))
        visited_code_nodes: set[str] = set()
        while queue:
            edge = queue.pop(0)
            target_id = str(edge.get("target", ""))
            target_role = role_by_node_id.get(target_id)
            if target_role:
                add_projected_edge(source_role, target_role, source_edge=edge)
                continue
            target_node = nodes_by_id.get(target_id, {})
            if target_node.get("type") != "code_block" or target_id in visited_code_nodes:
                continue
            visited_code_nodes.add(target_id)
            queue.extend(outgoing.get(target_id, []))

    for (source_id, target_id), risk_ids in edge_risk_ids.items():
        source_role = source_id.rsplit(":", 1)[-1]
        target_role = target_id.rsplit(":", 1)[-1]
        add_projected_edge(source_role, target_role, risk_ids=risk_ids)

    active_roles = {
        role
        for role, members in category_members.items()
        if members and (
            not flow_planes
            or any(
                edge.get("source") in {member.get("id") for member in members}
                or edge.get("target") in {member.get("id") for member in members}
                for edge in visible_edges
            )
            or any(f"{view_id}:{role}" in ids for ids in path_role_ids.values())
        )
    }
    for edge in projected_edges.values():
        active_roles.add(edge["source"].rsplit(":", 1)[-1])
        active_roles.add(edge["target"].rsplit(":", 1)[-1])
    if not active_roles and category_members:
        active_roles = set(category_members)

    severity_by_path = {
        path_id: str(path.get("severity", "unknown")).lower()
        for path_id, path in path_by_id.items()
    }
    projection_nodes = []
    for role, members in category_members.items():
        if role not in active_roles:
            continue
        label, layer, group, color = _OVERVIEW_ROLE_META[role]
        member_risk_ids = sorted({
            risk_id
            for member in members
            for risk_id in member.get("risk_hypothesis_ids", []) or []
        })
        projection_nodes.append({
            "id": f"{view_id}:{role}",
            "label": label,
            "type": role,
            "layer": layer,
            "style": {
                "group": group,
                "color": color,
                "shape": "semantic",
                "risk": bool(set(member_risk_ids) & selected_risk_ids),
                "risk_color": "#dc2626",
            },
            "security": {
                "trust_zone": "mixed" if len({item.get("security", {}).get("trust_zone") for item in members}) > 1 else members[0].get("security", {}).get("trust_zone"),
                "privilege_level": "mixed" if len({item.get("security", {}).get("privilege_level") for item in members}) > 1 else members[0].get("security", {}).get("privilege_level"),
                "asset_type": ", ".join(sorted({str(item.get("security", {}).get("asset_type")) for item in members if item.get("security", {}).get("asset_type")})),
                "threat_categories": sorted({
                    str(category)
                    for item in members
                    for category in item.get("security", {}).get("threat_categories", []) or []
                }),
                "risk_level": max(
                    (severity_by_path.get(risk_id, "unknown") for risk_id in member_risk_ids),
                    key=lambda severity: _SEVERITY_RANK.get(severity, 0),
                    default="not classified",
                ),
            },
            "risk_hypothesis_ids": member_risk_ids,
            "evidence": _projection_evidence(member.get("evidence", {}) for member in members),
            "attributes": {
                "semantic_role": role,
                "represented_node_count": len(members),
                "represented_node_ids": sorted(str(member["id"]) for member in members),
                "represented_node_types": sorted({str(member.get("type", "")) for member in members}),
                "source_trace_available": True,
                "projection_note": "This node is an aggregation. Switch to source trace to inspect individual files and functions.",
            },
        })

    allowed_ids = {node["id"] for node in projection_nodes}
    projection_edges = []
    for edge in projected_edges.values():
        if edge["source"] not in allowed_ids or edge["target"] not in allowed_ids:
            continue
        risk_ids = sorted(edge["risk_hypothesis_ids"])
        projection_edges.append({
            "id": edge["id"],
            "source": edge["source"],
            "target": edge["target"],
            "relation": ", ".join(sorted(edge["relations"])) or "risk path",
            "semantic_relation": "semantic_flow",
            "flow_planes": sorted(edge["flow_planes"]),
            "evidence": _projection_evidence(edge["evidence_items"]),
            "style": {
                "risk": bool(set(risk_ids) & selected_risk_ids),
                "color": "#dc2626" if set(risk_ids) & selected_risk_ids else "#94a3b8",
                "width": 3 if set(risk_ids) & selected_risk_ids else 1,
            },
            "risk_hypothesis_ids": risk_ids,
            "attributes": {
                "represented_edge_count": len(edge["represented_edge_ids"]),
                "represented_edge_ids": sorted(edge["represented_edge_ids"]),
                "projection_note": "Implementation edges are collapsed into this semantic relation.",
            },
        })

    projected_paths = []
    for path in risk_paths:
        path_id = str(path.get("id", ""))
        if flow_planes and not (set(path.get("flow_planes", []) or []) & flow_planes):
            continue
        mapped_path = [node_id for node_id in path_role_ids.get(path_id, []) if node_id in allowed_ids]
        if not mapped_path:
            continue
        projected_paths.append({
            **path,
            "source_path_node_ids": list(path.get("path_node_ids", []) or []),
            "path_node_ids": mapped_path,
        })

    collapsed_nodes = sum(1 for node in nodes if node.get("type") == "code_block")
    return {
        "id": view_id,
        "title": title,
        "nodes": sorted(projection_nodes, key=lambda node: (node["layer"], node["label"])),
        "edges": sorted(projection_edges, key=lambda edge: (edge["source"], edge["target"])),
        "risk_paths": projected_paths,
        "prioritized_risk_path_ids": list(selected_risk_ids),
        "collapsed_implementation_node_count": collapsed_nodes,
        "source_node_count": len(nodes),
        "source_edge_count": len(edges),
        "claim_boundary": "Semantic aggregation is a navigation aid; it does not create runtime evidence or confirm a vulnerability.",
    }


_NON_SEMANTIC_ATTRIBUTE_KEYS = {
    "observations",
    "declaration_source",
    "artifact_id",
    "artifact_ref",
    "artifact_refs",
    "evidence_ref",
    "observation_id",
    "run_id",
    "session_id",
    "task_id",
    "tool_execution_id",
    "generated_at",
}


def _semantic_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _semantic_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key) not in _NON_SEMANTIC_ATTRIBUTE_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_semantic_value(item) for item in value]
    if isinstance(value, set):
        return sorted(_semantic_value(item) for item in value)
    return value


def _fingerprint_evidence(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: _semantic_value(value[key])
        for key in ("level", "confidence", "source", "reason")
        if key in value
    }


def _fingerprint_node(node: "RuntimeSurfaceNode") -> dict[str, Any]:
    return {
        "id": node.node_id,
        "type": node.node_type,
        "label": node.label,
        "attributes": _semantic_value(node.attributes),
        "evidence": _fingerprint_evidence(node.evidence or {}),
    }


def _fingerprint_edge(edge: "RuntimeSurfaceEdge") -> dict[str, Any]:
    return {
        "source": edge.source,
        "target": edge.target,
        "relation": edge.relation,
        "semantic_relation": edge.semantic_relation or edge.relation,
        "flow_planes": sorted(edge.flow_planes),
        "attributes": _semantic_value(edge.attributes),
        "evidence": _fingerprint_evidence(edge.evidence or {}),
    }


@dataclass
class ProjectProfile:
    project_path: str
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    entry_points: list[dict[str, Any]] = field(default_factory=list)
    dependencies: dict[str, Any] = field(default_factory=dict)
    sensitive_files: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    insights: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ProjectProfile":
        tech = value.get("tech_stack", {})
        return cls(
            project_path=value.get("project_path", ""),
            languages=list(value.get("languages", tech.get("languages", []))),
            frameworks=list(value.get("frameworks", tech.get("frameworks", []))),
            entry_points=list(value.get("entry_points", [])),
            dependencies=dict(value.get("dependencies", {})),
            sensitive_files=list(value.get("sensitive_files", value.get("sensitive_config_files", []))),
            commands=list(value.get("commands", [])),
            insights=list(value.get("insights", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "languages": self.languages,
            "frameworks": self.frameworks,
            "entry_points": self.entry_points,
            "dependencies": self.dependencies,
            "sensitive_files": self.sensitive_files,
            "commands": self.commands,
            "insights": self.insights,
        }


@dataclass
class RuntimeSurfaceNode:
    node_id: str
    node_type: str
    label: str
    attributes: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "type": self.node_type,
            "label": self.label,
            "attributes": self.attributes,
            "evidence": self.evidence,
        }


@dataclass
class RuntimeSurfaceEdge:
    source: str
    target: str
    relation: str
    attributes: dict[str, Any] = field(default_factory=dict)
    semantic_relation: str = ""
    flow_planes: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "attributes": self.attributes,
            "semantic_relation": self.semantic_relation or self.relation,
            "flow_planes": self.flow_planes,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class RuntimeGraphObservation:
    observation_id: str
    target_kind: str
    target_id: str
    evidence_level: str
    source_agent: str
    source_tool: str = ""
    evidence_ref: str = ""
    confidence: float = 0.5
    facts: dict[str, Any] = field(default_factory=dict)
    hypothesis_ids: list[str] = field(default_factory=list)
    trust_class: str = "external"
    provenance: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RuntimeGraphObservation":
        observation = cls(
            observation_id=str(value.get("id") or value.get("observation_id") or ""),
            target_kind=str(value.get("target_kind", "")),
            target_id=str(value.get("target_id", "")),
            evidence_level=str(value.get("evidence_level", "")),
            source_agent=str(value.get("source_agent", "")),
            source_tool=str(value.get("source_tool", "")),
            evidence_ref=str(value.get("evidence_ref", "")),
            confidence=float(value.get("confidence", 0.5)),
            facts=dict(value.get("facts") or {}),
            hypothesis_ids=list(value.get("hypothesis_ids", []) or []),
            trust_class=str(value.get("trust_class", "external")),
            provenance=dict(value.get("provenance") or {}),
        )
        observation.validate()
        return observation

    def validate(self) -> None:
        valid_levels = {item.value for item in EvidenceLevel} - {EvidenceLevel.UNKNOWN.value}
        if not self.observation_id or not self.target_id or not self.source_agent:
            raise ValueError("observation id, target id, and source agent are required")
        if self.target_kind not in {"node", "edge"}:
            raise ValueError("target_kind must be node or edge")
        if self.trust_class not in {"external", "harness"}:
            raise ValueError("trust_class must be external or harness")
        if self.evidence_level not in valid_levels:
            raise ValueError(f"unsupported evidence level: {self.evidence_level}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("observation confidence must be between 0 and 1")
        if self.evidence_level in {
            EvidenceLevel.STATIC_OBSERVED.value,
            EvidenceLevel.RUNTIME_OBSERVED.value,
            EvidenceLevel.VERIFIED.value,
        } and (not self.source_tool or not self.evidence_ref):
            raise ValueError("observed or verified evidence requires source_tool and evidence_ref")
        if self.evidence_level == EvidenceLevel.VERIFIED.value and not self.facts.get("verification_predicate"):
            raise ValueError("verified evidence requires a verification_predicate")
        if self.evidence_level == EvidenceLevel.VERIFIED.value:
            if self.trust_class != "harness":
                raise ValueError("verified evidence requires Harness trust")
            if "verification" not in self.source_agent.lower():
                raise ValueError("verified evidence must be issued by a verification agent")
        if self.trust_class == "harness" and not self.provenance.get("run_id"):
            raise ValueError("Harness observations require run provenance")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.observation_id,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "evidence_level": self.evidence_level,
            "source_agent": self.source_agent,
            "source_tool": self.source_tool,
            "evidence_ref": self.evidence_ref,
            "confidence": self.confidence,
            "facts": self.facts,
            "hypothesis_ids": self.hypothesis_ids,
            "trust_class": self.trust_class,
            "provenance": self.provenance,
        }


@dataclass
class RuntimeSurfaceGraph:
    nodes: list[RuntimeSurfaceNode] = field(default_factory=list)
    edges: list[RuntimeSurfaceEdge] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def node_ids(self) -> list[str]:
        return [node.node_id for node in self.nodes]

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RuntimeSurfaceGraph":
        graph = cls(
            nodes=[RuntimeSurfaceNode(
                str(item.get("id", "")), str(item.get("type", "")),
                str(item.get("label", "")), dict(item.get("attributes") or {}),
                dict(item.get("evidence") or {}),
            ) for item in value.get("nodes", [])],
            edges=[RuntimeSurfaceEdge(
                str(item.get("source", "")), str(item.get("target", "")),
                str(item.get("relation", "")), dict(item.get("attributes") or {}),
                str(item.get("semantic_relation", "")), list(item.get("flow_planes", []) or []),
                dict(item.get("evidence") or {}),
            ) for item in value.get("edges", [])],
            metadata=dict(value.get("metadata") or {}),
        )
        enrich_runtime_graph(graph)
        return graph

    def content_fingerprint(self) -> str:
        payload = {
            "nodes": sorted((_fingerprint_node(item) for item in self.nodes), key=lambda item: item["id"]),
            "edges": sorted(
                (_fingerprint_edge(item) for item in self.edges),
                key=lambda item: (item["source"], item["target"], item["relation"]),
            ),
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
        return sha256(encoded).hexdigest()

    def diff(self, previous: "RuntimeSurfaceGraph") -> dict[str, Any]:
        current_nodes = {item.node_id: item.to_dict() for item in self.nodes}
        previous_nodes = {item.node_id: item.to_dict() for item in previous.nodes}
        current_edges = {_edge_identity(item): item.to_dict() for item in self.edges}
        previous_edges = {_edge_identity(item): item.to_dict() for item in previous.edges}
        return {
            "schema": "vibe-sec.vrtm.graph-diff.v1",
            "previous_fingerprint": previous.content_fingerprint(),
            "current_fingerprint": self.content_fingerprint(),
            "added_nodes": sorted(set(current_nodes) - set(previous_nodes)),
            "removed_nodes": sorted(set(previous_nodes) - set(current_nodes)),
            "changed_nodes": sorted(
                key for key in set(current_nodes) & set(previous_nodes)
                if current_nodes[key] != previous_nodes[key]
            ),
            "added_edges": sorted(set(current_edges) - set(previous_edges)),
            "removed_edges": sorted(set(previous_edges) - set(current_edges)),
            "changed_edges": sorted(
                key for key in set(current_edges) & set(previous_edges)
                if current_edges[key] != previous_edges[key]
            ),
        }

    def apply_observations(self, values: Iterable[dict[str, Any]]) -> dict[str, Any]:
        """Apply evidence-bound observations to existing graph entities."""
        previous = RuntimeSurfaceGraph.from_dict(self.to_dict())
        nodes = {item.node_id: item for item in self.nodes}
        edges = {_edge_identity(item): item for item in self.edges}
        accepted: list[str] = []
        superseded: list[str] = []
        rejected: list[dict[str, str]] = []
        seen: set[str] = {
            str(record.get("id"))
            for target in [*self.nodes, *self.edges]
            for record in target.attributes.get("observations", []) or []
            if isinstance(record, dict) and record.get("id")
        }
        rank = {
            EvidenceLevel.UNKNOWN.value: 0,
            EvidenceLevel.INFERRED.value: 1,
            EvidenceLevel.DECLARED.value: 2,
            EvidenceLevel.STATIC_OBSERVED.value: 3,
            EvidenceLevel.RUNTIME_OBSERVED.value: 4,
            EvidenceLevel.VERIFIED.value: 5,
        }
        allowed_node_facts = {
            "mcp_capability": {"authorization"},
            "storage_asset": {"access_control"},
            "trust_boundary": {"validation_mechanism"},
            "prompt": {"has_injection_protection"},
            "browser_sink": {"sanitization_detected"},
            "permission": {"enforced", "bypass_risks"},
        }
        allowed_edge_facts = {
            "trust_crossing", "requires_authorization", "approval_required",
            "runtime_observation", "verification_ref",
        }

        for value in values:
            observation_id = str(
                value.get("id") or value.get("observation_id") or ""
            ) if isinstance(value, dict) else ""
            try:
                if not isinstance(value, dict):
                    raise TypeError("observation must be an object")
                observation = RuntimeGraphObservation.from_dict(value)
                if observation.observation_id in seen:
                    raise ValueError("duplicate observation id")
                seen.add(observation.observation_id)
                target = nodes.get(observation.target_id) if observation.target_kind == "node" else edges.get(observation.target_id)
                if target is None:
                    raise ValueError("target does not exist in the current graph")

                attributes = target.attributes
                records = attributes.setdefault("observations", [])
                records.append(observation.to_dict())
                allowed_facts = (
                    allowed_node_facts.get(target.node_type, set())
                    if observation.target_kind == "node"
                    else allowed_edge_facts
                )
                current_level = str((target.evidence or {}).get("level", EvidenceLevel.UNKNOWN.value))
                can_replace = rank[observation.evidence_level] >= rank.get(current_level, 0)
                if can_replace:
                    attributes.setdefault("observed_facts", {}).update(observation.facts)
                if can_replace and observation.evidence_level != EvidenceLevel.INFERRED.value:
                    for key in allowed_facts:
                        if key in observation.facts:
                            attributes[key] = observation.facts[key]

                if can_replace:
                    target.evidence = {
                        "level": observation.evidence_level,
                        "confidence": observation.confidence,
                        "source": "agent_observation",
                        "source_agent": observation.source_agent,
                        "source_tool": observation.source_tool,
                        "evidence_ref": observation.evidence_ref,
                        "observation_id": observation.observation_id,
                    }
                else:
                    superseded.append(observation.observation_id)
                accepted.append(observation.observation_id)
            except (AttributeError, TypeError, ValueError) as exc:
                rejected.append({
                    "observation_id": observation_id,
                    "reason": str(exc),
                })

        enrich_runtime_graph(self)
        self.metadata["fingerprint"] = self.content_fingerprint()
        graph_diff = self.diff(previous)
        return {
            "schema": "vibe-sec.vrtm.observation-application.v1",
            "accepted_observation_ids": accepted,
            "superseded_observation_ids": superseded,
            "rejected_observations": rejected,
            "previous_fingerprint": graph_diff["previous_fingerprint"],
            "current_fingerprint": graph_diff["current_fingerprint"],
            "graph_diff": graph_diff,
        }

    def to_visualization(self, threat_model: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return a frontend-ready layered graph projection without losing source ids."""
        threat_model = dict(threat_model or {})
        hypotheses = list(threat_model.get("hypotheses", []))
        node_risks: dict[str, list[str]] = {node.node_id: [] for node in self.nodes}
        edge_risks: dict[tuple[str, str], list[str]] = {}
        for hypothesis in hypotheses:
            hypothesis_id = str(hypothesis.get("id", ""))
            path = [str(item) for item in hypothesis.get("attack_path", [])]
            for node_id in path:
                node_risks.setdefault(node_id, []).append(hypothesis_id)
            for source, target in zip(path, path[1:], strict=False):
                edge_risks.setdefault((source, target), []).append(hypothesis_id)

        layer_by_type = {
            "external_actor": 0,
            "human_operator": 0,
            "coding_agent": 0,
            "service_identity": 0,
            "external_content": 0,
            "external_service": 0,
            "entry_point": 1,
            "workflow": 1,
            "runtime_agent": 2,
            "prompt": 2,
            "model": 2,
            "memory": 2,
            "retriever": 2,
            "code_block": 2,
            "tool": 3,
            "mcp_capability": 3,
            "code_execution": 3,
            "deployment_capability": 3,
            "trust_boundary": 3,
            "permission": 3,
            "security_control": 3,
            "approval_control": 3,
            "policy_gateway": 3,
            "browser_sink": 4,
            "storage_asset": 4,
            "privileged_asset": 4,
            "secret_asset": 4,
            "source_artifact": 4,
            "deployment_asset": 4,
        }
        style_by_type = {
            "external_actor": {"group": "source", "color": "#b42318", "shape": "actor"},
            "human_operator": {"group": "source", "color": "#9a3412", "shape": "actor"},
            "coding_agent": {"group": "source", "color": "#9333ea", "shape": "agent"},
            "runtime_agent": {"group": "context", "color": "#7e22ce", "shape": "agent"},
            "service_identity": {"group": "source", "color": "#0f766e", "shape": "identity"},
            "external_content": {"group": "source", "color": "#c2410c", "shape": "input"},
            "external_service": {"group": "source", "color": "#a16207", "shape": "service"},
            "entry_point": {"group": "entry", "color": "#d97706", "shape": "entry"},
            "workflow": {"group": "entry", "color": "#ca8a04", "shape": "workflow"},
            "prompt": {"group": "context", "color": "#7c3aed", "shape": "prompt"},
            "model": {"group": "context", "color": "#4f46e5", "shape": "model"},
            "memory": {"group": "context", "color": "#6d28d9", "shape": "storage"},
            "retriever": {"group": "context", "color": "#0369a1", "shape": "retriever"},
            "code_block": {"group": "implementation", "color": "#64748b", "shape": "code"},
            "tool": {"group": "capability", "color": "#2563eb", "shape": "tool"},
            "mcp_capability": {"group": "capability", "color": "#0369a1", "shape": "mcp"},
            "code_execution": {"group": "capability", "color": "#1d4ed8", "shape": "terminal"},
            "deployment_capability": {"group": "capability", "color": "#047857", "shape": "deployment"},
            "trust_boundary": {"group": "boundary", "color": "#0891b2", "shape": "boundary"},
            "permission": {"group": "control", "color": "#15803d", "shape": "control"},
            "security_control": {"group": "control", "color": "#15803d", "shape": "control"},
            "approval_control": {"group": "control", "color": "#166534", "shape": "approval"},
            "policy_gateway": {"group": "control", "color": "#0f766e", "shape": "gateway"},
            "browser_sink": {"group": "sink", "color": "#be123c", "shape": "browser"},
            "storage_asset": {"group": "asset", "color": "#9f1239", "shape": "storage"},
            "privileged_asset": {"group": "asset", "color": "#be123c", "shape": "asset"},
            "secret_asset": {"group": "asset", "color": "#9f1239", "shape": "secret"},
            "source_artifact": {"group": "asset", "color": "#475569", "shape": "artifact"},
            "deployment_asset": {"group": "asset", "color": "#047857", "shape": "deployment"},
        }
        nodes = []
        for node in self.nodes:
            risk_ids = sorted(set(node_risks.get(node.node_id, [])))
            style = dict(style_by_type.get(node.node_type, {"group": "other", "color": "#475569", "shape": "default"}))
            if risk_ids:
                style.update({"risk": True, "risk_color": "#dc2626"})
            nodes.append({
                "id": node.node_id,
                "label": node.label,
                "type": node.node_type,
                "layer": layer_by_type.get(node.node_type, 2),
                "style": style,
                "security": {
                    "trust_zone": node.attributes.get("trust_zone"),
                    "privilege_level": node.attributes.get("privilege_level"),
                    "asset_type": node.attributes.get("asset_type"),
                    "threat_categories": node.attributes.get("threat_categories", []),
                    "risk_level": node.attributes.get("risk_level"),
                },
                "risk_hypothesis_ids": risk_ids,
                "evidence": node.evidence,
                "attributes": node.attributes,
            })

        edges = []
        for edge in self.edges:
            risk_ids = sorted(set(edge_risks.get((edge.source, edge.target), [])))
            edges.append({
                "id": _edge_identity(edge),
                "source": edge.source,
                "target": edge.target,
                "relation": edge.relation,
                "semantic_relation": edge.semantic_relation or edge.relation,
                "flow_planes": edge.flow_planes,
                "evidence": edge.evidence,
                "style": {
                    "risk": bool(risk_ids),
                    "color": "#dc2626" if risk_ids else "#94a3b8",
                    "width": 3 if risk_ids else 1,
                },
                "risk_hypothesis_ids": risk_ids,
                "attributes": edge.attributes,
            })

        risk_paths = [
            {
                "id": hypothesis.get("id"),
                "title": hypothesis.get("title"),
                "technique_id": hypothesis.get("technique_id"),
                "severity": hypothesis.get("severity"),
                "confidence": hypothesis.get("confidence"),
                "source_node_ids": hypothesis.get("source_node_ids", []),
                "boundary_node_ids": hypothesis.get("boundary_node_ids", []),
                "target_node_ids": hypothesis.get("target_node_ids", []),
                "path_node_ids": hypothesis.get("attack_path", []),
                "impact": hypothesis.get("impact"),
                "evidence_predicates": hypothesis.get("evidence_predicates", []),
                "status": hypothesis.get("status", "open"),
                "flow_planes": hypothesis.get("flow_planes", []),
                "control_gaps": hypothesis.get("control_gaps", []),
                "risk_factors": hypothesis.get("risk_factors", {}),
                "external_mappings": hypothesis.get("external_mappings", {}),
            }
            for hypothesis in hypotheses
        ]
        views = {
            plane: {
                "edge_ids": [edge["id"] for edge in edges if plane in edge["flow_planes"]],
                "node_ids": sorted({
                    node_id
                    for edge in edges if plane in edge["flow_planes"]
                    for node_id in (edge["source"], edge["target"])
                }),
                "risk_path_ids": [
                    path["id"] for path in risk_paths if plane in path["flow_planes"]
                ],
            }
            for plane in ("data", "instruction", "authority", "artifact")
        }
        projections = {
            "risk_overview": _semantic_runtime_projection(
                nodes,
                edges,
                risk_paths,
                view_id="risk-overview",
                title="风险概览",
            ),
            "ai_agent": _semantic_runtime_projection(
                nodes,
                edges,
                risk_paths,
                view_id="ai-agent",
                title="AI / Agent 面",
                flow_planes={"instruction", "authority"},
            ),
            "data": _semantic_runtime_projection(
                nodes,
                edges,
                risk_paths,
                view_id="data-plane",
                title="数据面",
                flow_planes={"data"},
            ),
            "authority": _semantic_runtime_projection(
                nodes,
                edges,
                risk_paths,
                view_id="authority-plane",
                title="权限面",
                flow_planes={"authority"},
            ),
            "source_trace": {
                "id": "source-trace",
                "title": "源码追溯",
                "source_node_count": len(nodes),
                "source_edge_count": len(edges),
                "collapsed_implementation_node_count": 0,
                "claim_boundary": "Full source graph. Use only when tracing a selected risk to source evidence.",
            },
        }
        return {
            "schema": "vibe-sec.runtime-surface-visualization",
            "version": "1",
            "layout": {"algorithm": "layered", "direction": "LR", "layer_gap": 180, "node_gap": 80},
            "nodes": nodes,
            "edges": edges,
            "risk_paths": risk_paths,
            "views": views,
            "default_view": "risk_overview",
            "projections": projections,
            "coverage": self.metadata.get("coverage", {}),
            "fingerprint": self.metadata.get("fingerprint", self.content_fingerprint()),
            "legend": {
                "source": "Untrusted external actor or input",
                "entry": "Application entry point",
                "context": "Prompt or model context",
                "capability": "Tool or model-callable capability",
                "boundary": "Trust or authorization boundary",
                "sink": "Browser or rendering sink",
                "asset": "Privileged operation or protected asset",
                "red_path": "Node or edge included in a risk hypothesis",
            },
        }

    @classmethod
    def from_surface(cls, surface: Any) -> "RuntimeSurfaceGraph":
        graph = cls(metadata={"method": "runtime_surface_projection", "version": "4"})
        node_index: dict[tuple[str, str, Any, Any], str] = {}
        edge_index: set[tuple[str, str, str]] = set()

        def node_identity(node_type: str, label: str, attributes: dict[str, Any]) -> tuple[Any, ...]:
            """Use semantic anchors so an inserted source line does not redraw the runtime."""
            file_path = str(attributes.get("file_path", "")).replace("\\", "/")
            if node_type == "code_block":
                return (node_type, file_path, attributes.get("block_type", ""), label)
            if node_type == "entry_point":
                # A parsed handler is a stable semantic identity. Some fallback
                # extractors cannot recover it; keep those ambiguous duplicate
                # routes distinct instead of merging their auth state.
                handler = attributes.get("handler_function")
                return (
                    node_type, file_path, attributes.get("entry_type", ""),
                    attributes.get("method", ""), attributes.get("path", ""),
                    handler or attributes.get("line_start"),
                )
            if node_type == "trust_boundary":
                return (
                    node_type, file_path, attributes.get("boundary_type", ""),
                    attributes.get("source", ""), attributes.get("target", ""),
                )
            if node_type == "external_content":
                return (node_type, file_path, attributes.get("source_type", ""), label)
            if node_type == "storage_asset":
                return (
                    node_type, file_path, attributes.get("storage_type", ""),
                    attributes.get("operation", ""), label,
                )
            if node_type == "prompt":
                return (node_type, file_path, attributes.get("type", ""), label)
            if node_type == "model":
                return (
                    node_type, file_path, attributes.get("provider", ""),
                    attributes.get("operation", ""), label,
                )
            if node_type in {"tool", "mcp_capability", "permission", "workflow"}:
                return (node_type, file_path, label)
            if node_type == "browser_sink":
                return (node_type, file_path, attributes.get("sink_type", ""), label)
            return (node_type, label, file_path, attributes.get("line_start"))

        def add_node(node_type: str, label: str, attributes: dict[str, Any]) -> str:
            attributes = dict(attributes)
            key = node_identity(node_type, label, attributes)
            if key in node_index:
                return node_index[key]
            node_id = stable_id(*key)
            attributes.setdefault("provenance", {
                "file_path": attributes.get("file_path"),
                "line_start": attributes.get("line_start"),
                "line_end": attributes.get("line_end", attributes.get("line_start")),
            })
            graph.nodes.append(RuntimeSurfaceNode(node_id, node_type, label, attributes))
            node_index[key] = node_id
            return node_id

        def add_edge(source: str, target: str, relation: str, attributes: dict[str, Any]) -> None:
            if not source or not target or source == target:
                return
            key = (source, target, relation)
            if key in edge_index:
                return
            edge_index.add(key)
            value = dict(attributes)
            value.setdefault("provenance", "surface_extractor")
            graph.edges.append(RuntimeSurfaceEdge(source, target, relation, value))

        def in_file(mapping: dict[str, list[str]], file_path: str) -> list[str]:
            return list(mapping.get(file_path, []))

        actor_id = add_node(
            "external_actor",
            "external_user",
            {
                "actor_type": "external_user",
                "trust_zone": "untrusted",
                "threat_categories": ["injection", "unauthorized_access"],
            },
        )

        code_by_file: dict[str, list[str]] = {}
        code_by_name: dict[tuple[str, str], str] = {}
        code_by_short_name: dict[str, list[str]] = {}
        code_objects: dict[str, Any] = {}
        for block in getattr(surface, "code_blocks", []):
            attributes = block.to_dict()
            attributes.update({"trust_zone": "application_logic", "privilege_level": "application"})
            node_id = add_node("code_block", block.name, attributes)
            code_by_file.setdefault(block.file_path, []).append(node_id)
            code_by_name[(block.file_path, block.name)] = node_id
            code_by_short_name.setdefault(block.name.rsplit(".", 1)[-1], []).append(node_id)
            code_objects[node_id] = block

        # Resolve bounded call relationships from the source extractor. Same-file
        # calls are strong evidence; cross-file calls are only linked when the
        # symbol is globally unique, avoiding filename-wide false edges.
        for caller_id, caller in code_objects.items():
            for call in getattr(caller, "calls", []) or []:
                short_name = str(call).rsplit(".", 1)[-1]
                targets = code_by_short_name.get(short_name, [])
                same_file = [
                    target_id for target_id in targets
                    if code_objects[target_id].file_path == caller.file_path
                    and target_id != caller_id
                ]
                if same_file:
                    targets = same_file
                    confidence = "same_file_symbol"
                elif len(targets) == 1 and targets[0] != caller_id:
                    confidence = "unique_cross_file_symbol"
                else:
                    continue
                for target_id in targets[:8]:
                    add_edge(caller_id, target_id, "calls", {
                        "control_flow": "source_call_reference",
                        "call_name": str(call),
                        "confidence": confidence,
                        "security_meaning": "application_control_flow",
                    })

        permission_by_file: dict[str, list[str]] = {}
        for permission in getattr(surface, "permission_profiles", []):
            attributes = permission.to_dict()
            attributes.update({
                "trust_zone": "control_plane",
                "threat_categories": ["authorization_bypass"],
                "privilege_level": "security_control",
            })
            permission_id = add_node("permission", permission.permission_type, attributes)
            permission_by_file.setdefault(permission.file_path, []).append(permission_id)

        boundary_by_file: dict[str, list[str]] = {}
        for boundary in getattr(surface, "trust_boundaries", []):
            attributes = boundary.to_dict()
            attributes.update({
                "trust_zone": "boundary",
                "threat_categories": ["trust_boundary_bypass"],
                "privilege_level": "security_control",
            })
            boundary_id = add_node(
                "trust_boundary",
                f"{boundary.source}->{boundary.target}",
                attributes,
            )
            if boundary.file_path:
                boundary_by_file.setdefault(boundary.file_path, []).append(boundary_id)

        entry_by_file: dict[str, list[str]] = {}
        for entry in getattr(surface, "page_entries", []):
            attributes = entry.to_dict()
            attributes.update({
                "trust_zone": "application_boundary",
                "entry_point": True,
                "threat_categories": ["injection", "authorization_bypass"],
                "privilege_level": "application",
            })
            entry_id = add_node("entry_point", f"{entry.method} {entry.path}", attributes)
            entry_by_file.setdefault(entry.file_path, []).append(entry_id)
            add_edge(actor_id, entry_id, "supplies_input", {
                "data_classification": "untrusted", "trust_crossing": True,
                "security_meaning": "untrusted_input_flow",
            })
            handler_id = code_by_name.get((entry.file_path, entry.handler_function or ""))
            if not handler_id and entry.handler_function:
                handler_targets = code_by_short_name.get(str(entry.handler_function).rsplit(".", 1)[-1], [])
                handler_id = handler_targets[0] if len(handler_targets) == 1 else None
            targets = [handler_id] if handler_id else [
                target_id for target_id in in_file(code_by_file, entry.file_path)
                if code_objects[target_id].contains_user_input
                or code_objects[target_id].contains_dangerous_operations
            ]
            for target_id in filter(None, targets):
                add_edge(entry_id, target_id, "implemented_by", {
                    "data_flow": "request_to_application_logic",
                    "security_meaning": "control_influence",
                })
            for control_id in in_file(permission_by_file, entry.file_path):
                add_edge(entry_id, control_id, "governed_by", {
                    "authorization_control": True,
                    "security_meaning": "authorization_decision",
                })

        external_by_file: dict[str, list[str]] = {}
        external_objects: dict[str, Any] = {}
        for external in getattr(surface, "external_content_inputs", []):
            attributes = external.to_dict()
            attributes.update({
                "trust_zone": "untrusted",
                "threat_categories": ["injection", "prompt_injection", "ssrf"],
                "privilege_level": "external",
            })
            external_id = add_node("external_content", external.name, attributes)
            external_by_file.setdefault(external.file_path, []).append(external_id)
            external_objects[external_id] = external
            add_edge(actor_id, external_id, "controls", {
                "data_classification": "untrusted",
                "security_meaning": "untrusted_input_flow",
            })
            if external.source_type == "http_request":
                for entry_id in in_file(entry_by_file, external.file_path):
                    add_edge(entry_id, external_id, "provides", {
                        "data_flow": "request_field",
                        "security_meaning": "untrusted_input_flow",
                    })

        prompt_by_file: dict[str, list[str]] = {}
        prompt_objects: dict[str, Any] = {}
        for prompt in getattr(surface, "prompt_configs", []):
            attributes = prompt.to_dict()
            attributes.update({
                "trust_zone": "model_context",
                "threat_categories": ["prompt_injection", "indirect_injection"],
                "privilege_level": "model_controlled",
            })
            prompt_id = add_node("prompt", prompt.name, attributes)
            prompt_by_file.setdefault(prompt.file_path, []).append(prompt_id)
            prompt_objects[prompt_id] = prompt
            for target_id in in_file(code_by_file, prompt.file_path)[:1]:
                add_edge(prompt_id, target_id, "configured_in", {
                    "data_flow": "prompt_configuration",
                    "security_meaning": "instruction_influence",
                })
            candidates = in_file(external_by_file, prompt.file_path)
            explicit = [
                node_id for node_id in candidates
                if prompt.name in getattr(external_objects[node_id], "target_refs", [])
            ]
            if not explicit and len(candidates) == 1 and len(getattr(surface, "prompt_configs", [])) == 1:
                explicit = candidates
            for source_id in explicit:
                add_edge(source_id, prompt_id, "influences", {
                    "data_flow": "external_content_to_prompt",
                    "security_meaning": "instruction_influence",
                    "confidence": "explicit_reference" if prompt.name in getattr(external_objects[source_id], "target_refs", []) else "bounded_colocation",
                })

        model_by_file: dict[str, list[str]] = {}
        for model in getattr(surface, "model_invocations", []):
            attributes = model.to_dict()
            attributes.update({
                "trust_zone": "model_runtime",
                "threat_categories": ["prompt_injection", "excessive_agency"],
                "privilege_level": "model_controlled",
            })
            model_id = add_node("model", model.name, attributes)
            model_by_file.setdefault(model.file_path, []).append(model_id)
            prompt_candidates = in_file(prompt_by_file, model.file_path)
            explicit = [
                prompt_id for prompt_id in prompt_candidates
                if prompt_objects[prompt_id].name in model.prompt_refs
            ]
            if not explicit and len(prompt_candidates) == 1:
                explicit = prompt_candidates
            for prompt_id in explicit:
                add_edge(prompt_id, model_id, "supplies_instructions", {
                    "data_flow": "prompt_to_model",
                    "security_meaning": "instruction_influence",
                })
            for external_id in in_file(external_by_file, model.file_path):
                external = external_objects[external_id]
                if external.name not in model.prompt_refs:
                    continue
                add_edge(external_id, model_id, "supplies_content", {
                    "data_flow": "external_content_to_model",
                    "security_meaning": "instruction_influence",
                    "confidence": "explicit_reference",
                })

        tool_by_file: dict[str, list[str]] = {}
        tool_by_identity: dict[tuple[str, str], str] = {}
        for tool in getattr(surface, "tool_profiles", []):
            attributes = tool.to_dict()
            attributes.update({
                "trust_zone": "privileged_execution",
                "threat_categories": ["excessive_agency", "tool_misuse", "mcp_tool_poisoning"],
                "privilege_level": "high" if tool.risk_level in {"high", "critical"} else "medium",
            })
            tool_id = add_node("tool", tool.name, attributes)
            tool_by_file.setdefault(tool.file_path, []).append(tool_id)
            tool_by_identity[(tool.file_path, tool.name)] = tool_id
            for control_id in in_file(permission_by_file, tool.file_path):
                add_edge(tool_id, control_id, "governed_by", {
                    "authorization_control": True,
                    "security_meaning": "authorization_decision",
                })

            if tool.risk_level in {"high", "critical"}:
                asset_id = add_node(
                    "privileged_asset",
                    f"{tool.name}:privileged_operation",
                    {
                        "file_path": tool.file_path,
                        "line_start": tool.line_start,
                        "line_end": tool.line_start,
                        "asset_type": "privileged_operation",
                        "tool_name": tool.name,
                        "operations": tool.dangerous_operations,
                        "risk_level": tool.risk_level,
                        "trust_zone": "protected_asset",
                        "threat_categories": ["data_breach", "remote_code_execution", "privilege_escalation"],
                        "privilege_level": "critical",
                    },
                )
                add_edge(tool_id, asset_id, "accesses", {
                    "data_flow": "tool_to_privileged_operation",
                    "requires_authorization": bool(tool.requires_confirmation),
                    "security_meaning": "privileged_capability_access",
                })

        mcp_by_file: dict[str, list[str]] = {}
        for capability in getattr(surface, "mcp_capabilities", []):
            attributes = capability.to_dict()
            attributes.update({
                "trust_zone": "mcp_boundary",
                "threat_categories": ["mcp_tool_poisoning", "authorization_bypass", "excessive_agency"],
                "privilege_level": "high" if capability.consequential_operations else "medium",
                "risk_level": "high" if capability.consequential_operations else "medium",
            })
            capability_id = add_node("mcp_capability", f"{capability.server}:{capability.name}", attributes)
            mcp_by_file.setdefault(capability.file_path, []).append(capability_id)
            matching_tool = tool_by_identity.get((capability.file_path, capability.name))
            if matching_tool:
                add_edge(capability_id, matching_tool, "implemented_as", {
                    "control_flow": "mcp_registration_to_handler",
                    "security_meaning": "privileged_capability_access",
                })
            for boundary_id in in_file(boundary_by_file, capability.file_path):
                boundary = next(node for node in graph.nodes if node.node_id == boundary_id)
                if boundary.attributes.get("line_start") == capability.line_start:
                    add_edge(capability_id, boundary_id, "crosses", {
                        "trust_crossing": True,
                        "validation": boundary.attributes.get("validation_mechanism"),
                        "security_meaning": "authorization_decision",
                    })
            if capability.consequential_operations:
                asset_id = add_node("privileged_asset", f"{capability.name}:mcp_operation", {
                    "file_path": capability.file_path,
                    "line_start": capability.line_start,
                    "line_end": capability.line_end,
                    "asset_type": "privileged_operation",
                    "operations": capability.consequential_operations,
                    "risk_level": "high",
                    "trust_zone": "protected_asset",
                    "threat_categories": ["remote_code_execution", "data_breach"],
                    "privilege_level": "critical",
                })
                add_edge(capability_id, asset_id, "accesses", {
                    "security_meaning": "privileged_capability_access",
                    "requires_authorization": capability.authorization == "enforced",
                })

        for model in getattr(surface, "model_invocations", []):
            if not model.tool_enabled:
                continue
            for model_id in in_file(model_by_file, model.file_path):
                for target_id in in_file(mcp_by_file, model.file_path) or in_file(tool_by_file, model.file_path):
                    add_edge(model_id, target_id, "can_invoke", {
                        "control_flow": "model_to_capability",
                        "security_meaning": "privileged_capability_access",
                    })

        browser_by_file: dict[str, list[str]] = {}
        browser_objects: dict[str, Any] = {}
        for sink in getattr(surface, "browser_sinks", []):
            attributes = sink.to_dict()
            attributes.update({
                "trust_zone": "browser",
                "threat_categories": ["cross_site_scripting", "url_injection"],
                "privilege_level": "user_session",
                "risk_level": "high" if sink.dangerous and not sink.sanitization_detected else "low",
            })
            sink_id = add_node("browser_sink", sink.sink_type, attributes)
            browser_by_file.setdefault(sink.file_path, []).append(sink_id)
            browser_objects[sink_id] = sink
            candidates = in_file(external_by_file, sink.file_path)
            explicit = [
                external_id for external_id in candidates
                if set(sink.input_refs) & (
                    set(_identifier_refs_for_graph(external_objects[external_id].expression))
                    | {external_objects[external_id].name}
                )
            ]
            if not explicit and len(candidates) == 1:
                explicit = candidates
            for external_id in explicit:
                add_edge(external_id, sink_id, "renders_at", {
                    "data_flow": "external_content_to_browser_sink",
                    "security_meaning": "untrusted_input_flow",
                    "sanitization_detected": sink.sanitization_detected,
                })

        storage_by_file: dict[str, list[str]] = {}
        storage_objects: dict[str, Any] = {}
        for storage in getattr(surface, "storage_assets", []):
            attributes = storage.to_dict()
            attributes.update({
                "trust_zone": "persistent_data",
                "asset_type": storage.storage_type,
                "threat_categories": ["sensitive_data_exposure", "data_tampering"],
                "privilege_level": "protected" if storage.sensitive else "application",
                "risk_level": "high" if storage.sensitive else "medium",
            })
            storage_id = add_node("storage_asset", f"{storage.storage_type}:{storage.name}", attributes)
            storage_by_file.setdefault(storage.file_path, []).append(storage_id)
            storage_objects[storage_id] = storage
            relation = "writes" if storage.operation in {"write", "open"} else "reads"
            for source_id in in_file(tool_by_file, storage.file_path) + in_file(mcp_by_file, storage.file_path):
                add_edge(source_id, storage_id, relation, {
                    "data_flow": f"capability_to_{storage.storage_type}",
                    "security_meaning": "data_write_flow" if relation == "writes" else "data_read_flow",
                })

        workflow_jobs: dict[tuple[str, str, str], str] = {}
        for workflow in getattr(surface, "workflow_nodes", []):
            attributes = workflow.to_dict()
            attributes.update({
                "trust_zone": "automation",
                "threat_categories": ["workflow_injection", "credential_exposure", "supply_chain"],
                "privilege_level": "high" if workflow.capabilities else "application",
                "risk_level": "high" if workflow.untrusted_inputs and workflow.capabilities else "medium",
            })
            workflow_id = add_node("workflow", f"{workflow.workflow_name}:{workflow.node_name}", attributes)
            if workflow.node_type == "job":
                workflow_jobs[(workflow.file_path, workflow.workflow_name, workflow.node_name)] = workflow_id
                if workflow.untrusted_inputs:
                    add_edge(actor_id, workflow_id, "influences", {
                        "data_flow": "event_to_workflow",
                        "security_meaning": "untrusted_input_flow",
                    })
            else:
                job_name = workflow.node_name.split("/", 1)[0]
                parent_id = workflow_jobs.get((workflow.file_path, workflow.workflow_name, job_name))
                if parent_id:
                    add_edge(parent_id, workflow_id, "executes", {
                        "control_flow": "workflow_job_to_step",
                        "security_meaning": "control_influence",
                    })
            if workflow.capabilities:
                asset_id = add_node("privileged_asset", f"{workflow.workflow_name}:{workflow.node_name}:capabilities", {
                    "file_path": workflow.file_path,
                    "line_start": workflow.line_start,
                    "line_end": workflow.line_end,
                    "asset_type": "workflow_capability",
                    "operations": workflow.capabilities,
                    "risk_level": "high",
                    "trust_zone": "protected_asset",
                    "threat_categories": ["credential_exposure", "code_execution", "deployment_tampering"],
                    "privilege_level": "high",
                })
                add_edge(workflow_id, asset_id, "accesses", {
                    "security_meaning": "privileged_capability_access",
                    "requires_authorization": bool(workflow.permissions),
                })

        # Bind source/sink observations to the function or class whose source
        # range actually contains them. This is stronger than arbitrary
        # co-location and makes ordinary handlers, storage calls, and browser
        # sinks available to risk-path traversal.
        for code_id, block in code_objects.items():
            for external_id in in_file(external_by_file, block.file_path):
                external = external_objects[external_id]
                if block.line_start <= external.line_start <= block.line_end:
                    add_edge(external_id, code_id, "received_by", {
                        "data_flow": "external_content_to_code",
                        "confidence": "source_range_binding",
                        "security_meaning": "untrusted_input_flow",
                    })
            for sink_id in in_file(browser_by_file, block.file_path):
                sink = browser_objects[sink_id]
                if block.line_start <= sink.line_start <= block.line_end:
                    add_edge(code_id, sink_id, "renders_at", {
                        "data_flow": "code_to_browser_sink",
                        "confidence": "source_range_binding",
                        "security_meaning": "untrusted_input_flow",
                    })
            for storage_id in in_file(storage_by_file, block.file_path):
                storage = storage_objects[storage_id]
                if block.line_start <= storage.line_start <= block.line_end:
                    relation = "writes" if storage.operation in {"write", "open", "insert", "update"} else "reads"
                    add_edge(code_id, storage_id, relation, {
                        "data_flow": f"code_to_{storage.storage_type}",
                        "confidence": "source_range_binding",
                        "security_meaning": (
                            "data_write_flow" if relation == "writes" else "data_read_flow"
                        ),
                    })

        graph.metadata["node_count"] = len(graph.nodes)
        graph.metadata["edge_count"] = len(graph.edges)
        graph.metadata["source_grounded_edges"] = sum(
            edge.attributes.get("provenance") == "surface_extractor" for edge in graph.edges
        )
        graph.metadata["extraction_coverage"] = getattr(surface, "metadata", {}).get("extraction_coverage", {})
        enrich_runtime_graph(graph)
        connected_ids = {
            endpoint
            for edge in graph.edges
            for endpoint in (edge.source, edge.target)
        }
        isolated = [node for node in graph.nodes if node.node_id not in connected_ids]
        isolated_by_type: dict[str, int] = {}
        for node in isolated:
            isolated_by_type[node.node_type] = isolated_by_type.get(node.node_type, 0) + 1
        graph.metadata["isolated_node_count"] = len(isolated)
        graph.metadata["isolated_node_ratio"] = (
            round(len(isolated) / len(graph.nodes), 4) if graph.nodes else 0.0
        )
        graph.metadata["isolated_nodes_by_type"] = isolated_by_type
        graph.metadata["fingerprint"] = graph.content_fingerprint()
        return graph


def _identifier_refs_for_graph(text: str) -> set[str]:
    return set(re.findall(r"\b[A-Za-z_$][\w$]*\b", text))
