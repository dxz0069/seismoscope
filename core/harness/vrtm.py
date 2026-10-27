"""VRTM graph semantics shared by extraction, analysis, and visualization."""

from __future__ import annotations

from enum import Enum
from typing import Any


class FlowPlane(str, Enum):
    DATA = "data"
    INSTRUCTION = "instruction"
    AUTHORITY = "authority"
    ARTIFACT = "artifact"


class EvidenceLevel(str, Enum):
    DECLARED = "declared"
    STATIC_OBSERVED = "static_observed"
    INFERRED = "inferred"
    RUNTIME_OBSERVED = "runtime_observed"
    VERIFIED = "verified"
    UNKNOWN = "unknown"


# Canonical relation names → (canonical_name, flow_planes).
# These are the authoritative relation identifiers used in graph queries,
# lifecycle analysis, and security-change detection.
RELATION_SEMANTICS: dict[str, tuple[str, tuple[FlowPlane, ...]]] = {
    # ── Canonical relations (key == canonical_name) ───────────────────────
    "supplies_data":         ("supplies_data",          (FlowPlane.DATA,)),
    "influences_instruction":("influences_instruction", (FlowPlane.INSTRUCTION,)),
    "invokes":               ("invokes",                (FlowPlane.AUTHORITY, FlowPlane.ARTIFACT)),
    "delegates_authority":   ("delegates_authority",    (FlowPlane.AUTHORITY,)),
    "persists_to":           ("persists_to",            (FlowPlane.DATA, FlowPlane.ARTIFACT)),
    "loads_from":            ("loads_from",             (FlowPlane.DATA, FlowPlane.ARTIFACT)),
    "authenticates_as":      ("authenticates_as",       (FlowPlane.AUTHORITY,)),
    "crosses_boundary":      ("crosses_boundary",       (FlowPlane.DATA, FlowPlane.AUTHORITY)),
    "renders":               ("renders",                (FlowPlane.DATA,)),
    "navigates":             ("navigates",              (FlowPlane.DATA, FlowPlane.AUTHORITY)),
    "builds":                ("builds",                 (FlowPlane.ARTIFACT,)),
    "deploys":               ("deploys",                (FlowPlane.AUTHORITY, FlowPlane.ARTIFACT)),
    "approves":              ("approves",               (FlowPlane.AUTHORITY,)),
    "filters":               ("filters",               (FlowPlane.DATA, FlowPlane.INSTRUCTION)),
    "governs":               ("governs",               (FlowPlane.AUTHORITY,)),
    "reads":                 ("reads",                 (FlowPlane.DATA, FlowPlane.ARTIFACT)),
    "writes":                ("writes",                (FlowPlane.DATA, FlowPlane.ARTIFACT)),
    # ── Aliases (surface extractor / legacy names → canonical) ────────────
    # All aliases resolve to the same (canonical_name, planes) as the target
    # so that graph queries using edge.relation always get a canonical form
    # after passing through canonicalize_relation() / edge_semantics().
    "supplies_input":        ("supplies_data",          (FlowPlane.DATA,)),
    "provides":              ("supplies_data",          (FlowPlane.DATA,)),
    "controls":              ("supplies_data",          (FlowPlane.DATA,)),
    "implemented_by":        ("invokes",                (FlowPlane.DATA, FlowPlane.ARTIFACT)),
    "governed_by":           ("governs",               (FlowPlane.AUTHORITY,)),
    "configured_in":         ("persists_to",           (FlowPlane.INSTRUCTION, FlowPlane.ARTIFACT)),
    "influences":            ("influences_instruction", (FlowPlane.INSTRUCTION,)),
    "supplies_instructions": ("influences_instruction", (FlowPlane.INSTRUCTION,)),
    "supplies_content":      ("influences_instruction", (FlowPlane.DATA, FlowPlane.INSTRUCTION)),
    "can_invoke":            ("delegates_authority",   (FlowPlane.INSTRUCTION, FlowPlane.AUTHORITY)),
    "implemented_as":        ("invokes",               (FlowPlane.AUTHORITY, FlowPlane.ARTIFACT)),
    "crosses":               ("crosses_boundary",      (FlowPlane.AUTHORITY,)),
    "accesses":              ("delegates_authority",   (FlowPlane.DATA, FlowPlane.AUTHORITY)),
    "renders_at":            ("renders",               (FlowPlane.DATA,)),
    "executes":              ("invokes",               (FlowPlane.AUTHORITY, FlowPlane.ARTIFACT)),
}

# Reverse map: alias → canonical name for fast lookups without going through
# the full RELATION_SEMANTICS dict.
RELATION_ALIASES: dict[str, str] = {
    alias: canonical
    for alias, (canonical, _) in RELATION_SEMANTICS.items()
    if alias != canonical
}


def canonicalize_relation(relation: str) -> str:
    """Return the canonical relation name for *relation*.

    Graph analysis code (lifecycle diffs, security-change detection, threat
    hypothesis matching) must call this on every ``edge.relation`` value so that
    alias edges (e.g. ``"supplies_input"``, ``"influences"``) are treated
    identically to their canonical form (``"supplies_data"``,
    ``"influences_instruction"``).

    Returns *relation* unchanged if it is already canonical or unknown.
    """
    return RELATION_ALIASES.get(relation, relation)


NODE_GROUPS = {
    "external_actor": "principal",
    "human_operator": "principal",
    "coding_agent": "principal",
    "runtime_agent": "principal",
    "service_identity": "principal",
    "external_service": "interface",
    "external_content": "interface",
    "entry_point": "interface",
    "workflow": "execution",
    "prompt": "ai_context",
    "model": "ai_context",
    "memory": "ai_context",
    "retriever": "ai_context",
    "code_block": "execution",
    "tool": "capability",
    "mcp_capability": "capability",
    "code_execution": "capability",
    "deployment_capability": "capability",
    "trust_boundary": "boundary",
    "permission": "control",
    "security_control": "control",
    "approval_control": "control",
    "policy_gateway": "control",
    "browser_sink": "interface",
    "storage_asset": "asset",
    "privileged_asset": "asset",
    "secret_asset": "asset",
    "source_artifact": "asset",
    "deployment_asset": "asset",
}


def node_evidence(node_type: str, attributes: dict[str, Any]) -> dict[str, Any]:
    provenance = dict(attributes.get("provenance") or {})
    file_path = provenance.get("file_path") or attributes.get("file_path")
    declared = attributes.get("declaration_source")
    runtime = attributes.get("runtime_observation")
    verified = attributes.get("verification_ref")
    if verified:
        level, confidence, source = EvidenceLevel.VERIFIED, 1.0, "verification"
    elif runtime:
        level, confidence, source = EvidenceLevel.RUNTIME_OBSERVED, 0.95, "runtime"
    elif declared:
        level, confidence, source = EvidenceLevel.DECLARED, 0.7, "project_declaration"
    elif file_path:
        level, confidence, source = EvidenceLevel.STATIC_OBSERVED, 0.9, "source_extractor"
    elif node_type == "external_actor":
        level, confidence, source = EvidenceLevel.INFERRED, 0.5, "method_default"
    else:
        level, confidence, source = EvidenceLevel.UNKNOWN, 0.0, "unresolved"
    return {
        "level": level.value,
        "confidence": confidence,
        "source": source,
        "file_path": file_path,
        "line_start": provenance.get("line_start", attributes.get("line_start")),
        "line_end": provenance.get("line_end", attributes.get("line_end")),
    }


def edge_semantics(relation: str, attributes: dict[str, Any]) -> dict[str, Any]:
    # Resolve aliases to canonical form before looking up semantics so that
    # "supplies_input", "influences", etc. are treated identically to their
    # canonical counterparts by all downstream graph analysis code.
    canonical = canonicalize_relation(relation)
    semantic_relation, default_planes = RELATION_SEMANTICS.get(
        canonical, (canonical, (FlowPlane.DATA,)),
    )
    confidence_marker = str(attributes.get("confidence", ""))
    if confidence_marker == "explicit_reference":
        level, confidence = EvidenceLevel.STATIC_OBSERVED, 0.9
    elif confidence_marker == "bounded_colocation":
        level, confidence = EvidenceLevel.INFERRED, 0.55
    elif attributes.get("runtime_observation"):
        level, confidence = EvidenceLevel.RUNTIME_OBSERVED, 0.95
    elif attributes.get("verification_ref"):
        level, confidence = EvidenceLevel.VERIFIED, 1.0
    elif attributes.get("provenance") == "surface_extractor":
        level, confidence = EvidenceLevel.STATIC_OBSERVED, 0.82
    else:
        level, confidence = EvidenceLevel.INFERRED, 0.5
    return {
        "semantic_relation": semantic_relation,
        "flow_planes": [item.value for item in default_planes],
        "evidence": {
            "level": level.value,
            "confidence": confidence,
            "source": attributes.get("provenance", "surface_model"),
            "reason": confidence_marker or attributes.get("security_meaning"),
        },
    }


def enrich_runtime_graph(graph: Any) -> dict[str, Any]:
    for node in graph.nodes:
        node.attributes.setdefault("entity_group", NODE_GROUPS.get(node.node_type, "other"))
        if not node.evidence or not node.evidence.get("level"):
            node.evidence = node_evidence(node.node_type, node.attributes)
        node.attributes["evidence_level"] = node.evidence["level"]
        if node.node_type in {"permission", "security_control", "approval_control", "policy_gateway"}:
            enforced = bool(node.attributes.get("enforced"))
            bypasses = list(node.attributes.get("bypass_risks", []) or [])
            node.attributes["control"] = {
                "type": node.attributes.get(
                    "control_type", node.attributes.get("permission_type", node.node_type),
                ),
                "enforcement_state": "enforced" if enforced else "missing",
                "effectiveness": "partial" if bypasses else "implemented" if enforced else "missing",
                "verification_state": node.evidence["level"],
                "bypass_risks": bypasses,
            }
        elif node.node_type == "trust_boundary":
            validation = node.attributes.get("validation_mechanism")
            node.attributes["control"] = {
                "type": "trust_boundary_validation",
                "enforcement_state": "detected" if validation else "unknown",
                "effectiveness": "implemented" if validation else "unknown",
                "verification_state": node.evidence["level"],
            }

    for edge in graph.edges:
        semantics = edge_semantics(edge.relation, edge.attributes)
        edge.semantic_relation = edge.semantic_relation or semantics["semantic_relation"]
        edge.flow_planes = edge.flow_planes or semantics["flow_planes"]
        if not edge.evidence or not edge.evidence.get("level"):
            edge.evidence = semantics["evidence"]
        edge.attributes.setdefault("semantic_relation", edge.semantic_relation)
        edge.attributes.setdefault("flow_planes", list(edge.flow_planes))
        edge.attributes["evidence_level"] = edge.evidence["level"]

    coverage = runtime_graph_coverage(graph)
    graph.metadata.update({
        "schema": "vibe-sec.vrtm.graph.v1",
        "methodology": "VRTM",
        "methodology_version": "0.1",
        "flow_planes": [item.value for item in FlowPlane],
        "coverage": coverage,
    })
    return coverage


def runtime_graph_coverage(graph: Any) -> dict[str, Any]:
    plane_counts = {item.value: 0 for item in FlowPlane}
    evidence_counts = {item.value: 0 for item in EvidenceLevel}
    unknowns: list[dict[str, Any]] = []
    for node in graph.nodes:
        level = str((node.evidence or {}).get("level", EvidenceLevel.UNKNOWN.value))
        evidence_counts[level] = evidence_counts.get(level, 0) + 1
        if node.node_type == "mcp_capability" and node.attributes.get("authorization") == "unknown":
            unknowns.append({"kind": "authorization", "node_id": node.node_id})
        if node.node_type == "storage_asset" and node.attributes.get("access_control") == "unknown":
            unknowns.append({"kind": "storage_access_control", "node_id": node.node_id})
        if node.node_type == "trust_boundary" and not node.attributes.get("validation_mechanism"):
            unknowns.append({"kind": "boundary_validation", "node_id": node.node_id})
        if node.node_type == "service_identity" and not (
            node.attributes.get("permissions") or node.attributes.get("authorization")
        ):
            unknowns.append({"kind": "identity_permissions", "node_id": node.node_id})
        if node.node_type in {"runtime_agent", "coding_agent"} and not node.attributes.get("capabilities"):
            unknowns.append({"kind": "agent_capabilities", "node_id": node.node_id})
        if node.node_type == "external_service" and not node.attributes.get("authentication"):
            unknowns.append({"kind": "external_service_authentication", "node_id": node.node_id})
        if node.node_type in {"deployment_asset", "secret_asset"} and not node.attributes.get("access_control"):
            unknowns.append({"kind": "asset_access_control", "node_id": node.node_id})
    for edge in graph.edges:
        for plane in edge.flow_planes:
            plane_counts[plane] = plane_counts.get(plane, 0) + 1
        level = str((edge.evidence or {}).get("level", EvidenceLevel.UNKNOWN.value))
        evidence_counts[level] = evidence_counts.get(level, 0) + 1
    return {
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "node_type_counts": {
            node_type: sum(node.node_type == node_type for node in graph.nodes)
            for node_type in sorted({node.node_type for node in graph.nodes})
        },
        "flow_plane_edge_counts": plane_counts,
        "evidence_counts": evidence_counts,
        "inferred_edge_count": sum(
            edge.evidence.get("level") == EvidenceLevel.INFERRED.value for edge in graph.edges
        ),
        "unknown_count": len(unknowns),
        "unknowns": unknowns[:200],
    }
