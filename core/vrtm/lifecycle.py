"""Risk lifecycle and security-significant graph change analysis."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from ..harness.models import RuntimeGraphObservation, stable_id


def bind_hypothesis_statuses(threat_model: Any, observations: Iterable[Dict[str, Any]]) -> None:
    """Bind explicit audit/verification outcomes without treating model prose as proof.

    Only observations with trust_class == 'harness' (produced by the verification
    pipeline) are allowed to change a hypothesis status.  External / LLM-prose
    observations are intentionally ignored here.
    """
    from ..surface.threat_model import HypothesisStatus

    outcomes_by_id: Dict[str, set[str]] = {}
    for raw in observations:
        try:
            observation = RuntimeGraphObservation.from_dict(raw)
        except (TypeError, ValueError):
            continue
        if observation.trust_class != "harness":
            continue
        facts = observation.facts
        verification_status = str(facts.get("verification_status", ""))
        finding_verdict = str(facts.get("verdict", ""))
        remediation_status = str(facts.get("remediation_status", ""))
        if remediation_status in {"fixed", "mitigated", "retested"}:
            status = HypothesisStatus.MITIGATED
        elif verification_status == "rejected" or finding_verdict == "rejected":
            status = HypothesisStatus.REFUTED
        elif verification_status == "verified" or finding_verdict in {"confirmed", "supported"}:
            status = HypothesisStatus.SUPPORTED
        else:
            continue
        for hypothesis_id in observation.hypothesis_ids:
            outcomes_by_id.setdefault(hypothesis_id, set()).add(status)
    for hypothesis in threat_model.hypotheses:
        outcomes = outcomes_by_id.get(hypothesis.hypothesis_id, set())
        if HypothesisStatus.MITIGATED in outcomes:
            hypothesis.status = HypothesisStatus.MITIGATED
        elif HypothesisStatus.SUPPORTED in outcomes:
            hypothesis.status = HypothesisStatus.SUPPORTED
        elif HypothesisStatus.REFUTED in outcomes:
            hypothesis.status = HypothesisStatus.REFUTED


def compare_threat_models(current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, Any]:
    """Diff two threat model snapshots and classify every change.

    A hypothesis that existed in *previous* but is absent from *current* can
    disappear for two fundamentally different reasons:

    1. **graph_rebuild_loss** – The surface was rebuilt and the node or edge that
       triggered the hypothesis no longer exists (e.g. a renamed file, a deleted
       route).  This is NOT a security improvement; it means coverage shrank.
    2. **status_resolved** – The hypothesis id is still reachable in the current
       graph but it was explicitly marked "mitigated" or "refuted" by a harness
       observation.  This IS a genuine resolution.

    Because we only have the serialised threat models here (not the live graph),
    we use the hypothesis *status* in the *previous* snapshot as a proxy:
    - If the previous status was already "mitigated" or "refuted" the disappearance
      is consistent with a genuine resolution.
    - Otherwise we flag it as a potential graph-rebuild loss requiring review.
    """
    current_items = {str(item.get("id")): item for item in current.get("hypotheses", [])}
    previous_items = {str(item.get("id")): item for item in previous.get("hypotheses", [])}
    shared = set(current_items) & set(previous_items)
    changed = sorted(key for key in shared if current_items[key] != previous_items[key])
    status_changes = [
        {
            "hypothesis_id": key,
            "previous_status": previous_items[key].get("status", "open"),
            "current_status": current_items[key].get("status", "open"),
        }
        for key in shared
        if previous_items[key].get("status", "open") != current_items[key].get("status", "open")
    ]

    disappeared_ids = sorted(set(previous_items) - set(current_items))
    _resolved_statuses = {"mitigated", "refuted"}
    resolved_ids: List[str] = []
    graph_rebuild_loss_ids: List[str] = []
    for hyp_id in disappeared_ids:
        prev_status = str(previous_items[hyp_id].get("status", "open"))
        if prev_status in _resolved_statuses:
            resolved_ids.append(hyp_id)
        else:
            graph_rebuild_loss_ids.append(hyp_id)

    return {
        "schema": "vibe-sec.vrtm.threat-model-diff.v1",
        "new_hypothesis_ids": sorted(set(current_items) - set(previous_items)),
        # Deprecated alias kept for backwards compat – callers should prefer the
        # two fields below which distinguish genuine resolutions from coverage loss.
        "resolved_hypothesis_ids": disappeared_ids,
        "resolved_by_status_ids": resolved_ids,
        "graph_rebuild_loss_ids": graph_rebuild_loss_ids,
        "changed_hypothesis_ids": changed,
        "status_changes": status_changes,
        "new_hypothesis_count": len(set(current_items) - set(previous_items)),
        "resolved_hypothesis_count": len(resolved_ids),
        "graph_rebuild_loss_count": len(graph_rebuild_loss_ids),
        "requires_coverage_review": bool(graph_rebuild_loss_ids),
    }


def analyze_graph_changes(current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, Any]:
    current_nodes = {str(item.get("id")): item for item in current.get("nodes", [])}
    previous_nodes = {str(item.get("id")): item for item in previous.get("nodes", [])}
    current_edges = {_edge_id(item): item for item in current.get("edges", [])}
    previous_edges = {_edge_id(item): item for item in previous.get("edges", [])}
    added_edge_ids = set(current_edges) - set(previous_edges)
    added_node_ids = set(current_nodes) - set(previous_nodes)
    removed_node_ids = set(previous_nodes) - set(current_nodes)
    shared_edge_ids = set(current_edges) & set(previous_edges)
    shared_node_ids = set(current_nodes) & set(previous_nodes)

    _CONTROL_NODE_TYPES = {
        "security_control", "trust_boundary", "approval_control",
        "policy_gateway", "permission",
    }

    authority_expansion = [
        _edge_summary(edge_id, current_edges[edge_id])
        for edge_id in sorted(added_edge_ids)
        if "authority" in current_edges[edge_id].get("flow_planes", [])
    ]
    new_boundary_crossings = [
        _edge_summary(edge_id, current_edges[edge_id])
        for edge_id in sorted(added_edge_ids)
        if current_edges[edge_id].get("semantic_relation") == "crosses_boundary"
        or current_edges[edge_id].get("attributes", {}).get("trust_crossing") is True
    ]
    new_privileged_assets = [
        node_id for node_id in sorted(added_node_ids)
        if current_nodes[node_id].get("type") in {
            "privileged_asset", "secret_asset", "deployment_asset", "deployment_capability",
        }
        or current_nodes[node_id].get("attributes", {}).get("privilege_level") in {"high", "critical"}
    ]

    # Detect security control nodes that vanished between snapshots.
    # A disappearing trust_boundary or security_control is a potential coverage
    # regression, not an improvement, and must be surfaced for review.
    removed_control_nodes: List[Dict[str, Any]] = [
        _security_change(
            "CONTROL_NODE_REMOVED",
            "node",
            node_id,
            "node_type",
            previous_nodes[node_id].get("type"),
            None,
        )
        for node_id in sorted(removed_node_ids)
        if previous_nodes[node_id].get("type") in _CONTROL_NODE_TYPES
    ]

    control_regressions: List[Dict[str, Any]] = []
    control_improvements: List[Dict[str, Any]] = []
    strength = {"missing": 0, "unknown": 1, "partial": 2, "implemented": 3, "strong": 4}
    for node_id in sorted(shared_node_ids):
        before = previous_nodes[node_id].get("attributes", {}).get("control", {})
        after = current_nodes[node_id].get("attributes", {}).get("control", {})
        if not before and not after:
            continue
        before_state = str(before.get("effectiveness", "unknown"))
        after_state = str(after.get("effectiveness", "unknown"))
        change = {"node_id": node_id, "previous": before_state, "current": after_state}
        if strength.get(after_state, 1) < strength.get(before_state, 1):
            control_regressions.append(change)
        elif strength.get(after_state, 1) > strength.get(before_state, 1):
            control_improvements.append(change)

    security_attribute_changes: List[Dict[str, Any]] = list(removed_control_nodes)
    for edge_id in sorted(shared_edge_ids):
        before_edge = previous_edges[edge_id]
        after_edge = current_edges[edge_id]
        before_attributes = dict(before_edge.get("attributes", {}) or {})
        after_attributes = dict(after_edge.get("attributes", {}) or {})
        for attribute, reason_code in (
            ("requires_authorization", "AUTHORIZATION_REQUIREMENT_REMOVED"),
            ("approval_required", "APPROVAL_REQUIREMENT_REMOVED"),
        ):
            if before_attributes.get(attribute) is True and after_attributes.get(attribute) is not True:
                security_attribute_changes.append(_security_change(
                    reason_code, "edge", edge_id, attribute,
                    before_attributes.get(attribute), after_attributes.get(attribute),
                ))
        if not _has_wildcard(before_attributes.get("permissions")) and _has_wildcard(
            after_attributes.get("permissions")
        ):
            security_attribute_changes.append(_security_change(
                "EDGE_PERMISSION_WILDCARD_EXPANSION", "edge", edge_id, "permissions",
                before_attributes.get("permissions"), after_attributes.get("permissions"),
            ))
        before_crossing = (
            before_attributes.get("trust_crossing") is True
            or before_edge.get("semantic_relation") == "crosses_boundary"
        )
        after_crossing = (
            after_attributes.get("trust_crossing") is True
            or after_edge.get("semantic_relation") == "crosses_boundary"
        )
        if not before_crossing and after_crossing:
            security_attribute_changes.append(_security_change(
                "TRUST_CROSSING_ACTIVATED", "edge", edge_id, "trust_crossing",
                before_crossing, after_crossing,
            ))
        before_planes = set(before_edge.get("flow_planes", []) or [])
        after_planes = set(after_edge.get("flow_planes", []) or [])
        if "authority" not in before_planes and "authority" in after_planes:
            security_attribute_changes.append(_security_change(
                "AUTHORITY_FLOW_PLANE_ADDED", "edge", edge_id, "flow_planes",
                sorted(before_planes), sorted(after_planes),
            ))
        if _evidence_rank(after_edge) < _evidence_rank(before_edge):
            security_attribute_changes.append(_security_change(
                "EDGE_EVIDENCE_DOWNGRADED", "edge", edge_id, "evidence.level",
                _evidence_level(before_edge), _evidence_level(after_edge),
            ))

    for node_id in sorted(shared_node_ids):
        before_node = previous_nodes[node_id]
        after_node = current_nodes[node_id]
        before_attributes = dict(before_node.get("attributes", {}) or {})
        after_attributes = dict(after_node.get("attributes", {}) or {})
        if after_node.get("type") in {"service_identity", "runtime_agent", "coding_agent"}:
            permission_change = _permission_expansion(
                before_attributes.get("permissions"), after_attributes.get("permissions"),
            )
            if permission_change:
                security_attribute_changes.append(_security_change(
                    permission_change, "node", node_id, "permissions",
                    before_attributes.get("permissions"), after_attributes.get("permissions"),
                ))
        before_environment = _environment(before_attributes)
        after_environment = _environment(after_attributes)
        if _environment_rank(after_environment) > _environment_rank(before_environment):
            security_attribute_changes.append(_security_change(
                "ENVIRONMENT_PROMOTION", "node", node_id, "environment",
                before_environment, after_environment,
            ))
        before_classification = _classification(before_attributes)
        after_classification = _classification(after_attributes)
        if _classification_rank(after_classification) < _classification_rank(before_classification):
            security_attribute_changes.append(_security_change(
                "DATA_CLASSIFICATION_DOWNGRADED", "node", node_id, "data_classification",
                before_classification, after_classification,
            ))
        if after_node.get("type") in {
            "permission", "security_control", "approval_control", "policy_gateway", "trust_boundary",
        } and _evidence_rank(after_node) < _evidence_rank(before_node):
            security_attribute_changes.append(_security_change(
                "CONTROL_EVIDENCE_DOWNGRADED", "node", node_id, "evidence.level",
                _evidence_level(before_node), _evidence_level(after_node),
            ))

    previous_scope = dict(previous.get("metadata", {}).get("declaration", {}).get("scope", {}) or {})
    current_scope = dict(current.get("metadata", {}).get("declaration", {}).get("scope", {}) or {})
    if _environment_rank(str(current_scope.get("environment", ""))) > _environment_rank(
        str(previous_scope.get("environment", ""))
    ):
        security_attribute_changes.append(_security_change(
            "MODEL_SCOPE_ENVIRONMENT_PROMOTION", "model", "declaration-scope", "environment",
            previous_scope.get("environment"), current_scope.get("environment"),
        ))

    reason_codes = sorted({item["reason_code"] for item in security_attribute_changes})

    return {
        "schema": "vibe-sec.vrtm.security-change-analysis.v1",
        "authority_expansion": authority_expansion,
        "new_boundary_crossings": new_boundary_crossings,
        "new_privileged_asset_ids": new_privileged_assets,
        "control_regressions": control_regressions,
        "control_improvements": control_improvements,
        "security_attribute_changes": security_attribute_changes,
        "reason_codes": reason_codes,
        "removed_control_node_ids": [item["subject_id"] for item in removed_control_nodes],
        "requires_security_review": bool(
            authority_expansion or new_boundary_crossings or new_privileged_assets
            or control_regressions or security_attribute_changes or removed_control_nodes
        ),
        "review_reasons": [
            reason for condition, reason in (
                (authority_expansion, "authority_expansion"),
                (new_boundary_crossings, "new_boundary_crossing"),
                (new_privileged_assets, "new_privileged_asset"),
                (control_regressions, "control_regression"),
                (removed_control_nodes, "control_node_removed"),
                (security_attribute_changes, "security_attribute_regression"),
            ) if condition
        ],
    }


def _edge_id(edge: Dict[str, Any]) -> str:
    return stable_id("edge", edge.get("source"), edge.get("target"), edge.get("relation"))


def _edge_summary(edge_id: str, edge: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "edge_id": edge_id,
        "source": edge.get("source"),
        "target": edge.get("target"),
        "relation": edge.get("relation"),
        "semantic_relation": edge.get("semantic_relation"),
        "flow_planes": list(edge.get("flow_planes", []) or []),
        "evidence": dict(edge.get("evidence", {}) or {}),
    }


def _security_change(
    reason_code: str, subject_kind: str, subject_id: str, attribute: str,
    before: Any, after: Any,
) -> Dict[str, Any]:
    return {
        "reason_code": reason_code,
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "attribute": attribute,
        "before": before,
        "after": after,
    }


def _values(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, dict):
        values: set[str] = set()
        for key, item in value.items():
            if item is False or item is None or item == "":
                continue
            nested = _values(item)
            values.update(f"{key}:{part}" for part in nested or {"enabled"})
        return values
    if isinstance(value, (list, tuple, set)):
        return {str(item).strip() for item in value if str(item).strip()}
    return {part.strip() for part in str(value).split(",") if part.strip()}


def _has_wildcard(value: Any) -> bool:
    return any(item == "*" or item.endswith(":*") or item.lower() in {"admin", "administrator"} for item in _values(value))


def _permission_expansion(before: Any, after: Any) -> str:
    previous = _values(before)
    current = _values(after)
    if not _has_wildcard(before) and _has_wildcard(after):
        return "IDENTITY_PERMISSION_WILDCARD_EXPANSION"
    if previous and current - previous:
        return "IDENTITY_PERMISSION_EXPANSION"
    return ""


def _environment(attributes: Dict[str, Any]) -> str:
    scope = attributes.get("scope") if isinstance(attributes.get("scope"), dict) else {}
    return str(attributes.get("environment") or scope.get("environment") or attributes.get("deployment_environment") or "")


def _environment_rank(value: str) -> int:
    normalized = str(value).strip().lower()
    return {
        "": -1, "local": 0, "development": 0, "dev": 0,
        "test": 1, "testing": 1, "qa": 1,
        "staging": 2, "stage": 2, "preproduction": 2,
        "production": 3, "prod": 3,
    }.get(normalized, -1)


def _classification(attributes: Dict[str, Any]) -> str:
    return str(
        attributes.get("data_classification")
        or attributes.get("classification")
        or attributes.get("sensitivity")
        or ""
    )


def _classification_rank(value: str) -> int:
    return {
        "": -1, "public": 0, "internal": 1, "confidential": 2,
        "restricted": 3, "secret": 4, "top_secret": 5,
    }.get(str(value).strip().lower().replace(" ", "_"), -1)


def _evidence_level(value: Dict[str, Any]) -> str:
    evidence = dict(value.get("evidence", {}) or {})
    return str(evidence.get("level") or value.get("attributes", {}).get("evidence_level") or "unknown")


def _evidence_rank(value: Dict[str, Any]) -> int:
    return {
        "unknown": 0, "inferred": 1, "declared": 2,
        "static_observed": 3, "runtime_observed": 4, "verified": 5,
    }.get(_evidence_level(value), 0)
