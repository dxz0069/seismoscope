"""Product service for building, evolving, and persisting VRTM models."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from ..harness.models import RuntimeSurfaceGraph
from ..surface.runtime_surface import RuntimeSurfaceBuilder
from ..surface.threat_model import (
    TECHNIQUE_CATALOG_VERSION,
    VRTM_METHOD_VERSION,
    RuntimeThreatModelAnalyzer,
)
from .declaration import VRTMDeclaration
from .lifecycle import analyze_graph_changes, bind_hypothesis_statuses, compare_threat_models
from .observations import observations_from_verification
from .store import VRTMModelStore


class VRTMService:
    def __init__(self, project_path: str, *, store_root: Optional[str] = None):
        self.project_path = Path(project_path).resolve()
        if not self.project_path.is_dir():
            raise ValueError(f"project_path must be an existing directory: {project_path}")
        self.store = VRTMModelStore(str(self.project_path), root=store_root)

    async def build(
        self,
        *,
        declaration_path: Optional[str] = None,
        observations: Optional[Iterable[Dict[str, Any]]] = None,
        trusted_observations: Optional[Iterable[Dict[str, Any]]] = None,
        trusted_findings: Optional[Iterable[Dict[str, Any]]] = None,
        previous_result: Optional[Dict[str, Any]] = None,
        persist: bool = True,
        recon_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        # Callers may provide generators. Materialize them once so evidence counts
        # and the subsequent verification-observation pass see the same inputs.
        trusted_finding_values = [
            dict(item) for item in (trusted_findings or []) if isinstance(item, dict)
        ]
        previous_load_error = ""
        if previous_result is not None:
            previous = previous_result
        else:
            try:
                previous = self.store.load_latest()
            except ValueError as exc:
                previous = None
                previous_load_error = str(exc)
        surface = await RuntimeSurfaceBuilder(str(self.project_path)).build(recon_data=recon_data)
        graph = RuntimeSurfaceGraph.from_surface(surface)

        declaration = VRTMDeclaration.discover(str(self.project_path), declaration_path)
        declaration_application = declaration.merge_into(graph) if declaration else None
        base_fingerprint = graph.content_fingerprint()
        graph.metadata["base_fingerprint"] = base_fingerprint
        graph.metadata["base_graph_fingerprint"] = base_fingerprint
        external_observations = _classify_observations(observations, "external")
        harness_observations = _classify_observations(trusted_observations, "harness")
        incoming_observations = [*external_observations, *harness_observations]
        previous_observations: list[Dict[str, Any]] = []
        invalidated_observation_count = 0
        if previous:
            previous_graph_data = previous.get("graph") or previous.get("runtime_surface_graph") or {}
            stored = _stored_observations(previous_graph_data)
            if previous_graph_data.get("metadata", {}).get("base_fingerprint") == base_fingerprint:
                previous_observations = stored
            else:
                invalidated_observation_count = len(stored)
        observation_by_id = {
            str(item.get("id") or item.get("observation_id")): dict(item)
            for item in [*previous_observations, *incoming_observations]
            if isinstance(item, dict)
        }
        observation_values = list(observation_by_id.values())
        observation_application = graph.apply_observations(observation_values) if observation_values else None
        accepted_ids = set(
            observation_application.get("accepted_observation_ids", []) if observation_application else []
        )
        accepted_observations = [item for item in observation_values if item.get("id") in accepted_ids]

        threat_model = RuntimeThreatModelAnalyzer(surface, graph).analyze()
        retest_observation_application = None
        retest_diagnostics: list[Dict[str, Any]] = []
        if trusted_finding_values:
            retest_observations, retest_diagnostics = observations_from_verification(
                trusted_finding_values,
                graph,
                threat_model.to_dict(),
                run_id="retest",
            )
            if retest_observations:
                retest_observation_application = graph.apply_observations(retest_observations)
                accepted_retest_ids = set(
                    retest_observation_application.get("accepted_observation_ids", [])
                )
                accepted_observations.extend(
                    item for item in retest_observations if item.get("id") in accepted_retest_ids
                )
                observation_values.extend(retest_observations)
                threat_model = RuntimeThreatModelAnalyzer(surface, graph).analyze()
        bind_hypothesis_statuses(threat_model, accepted_observations)
        if declaration:
            threat_model.assumptions.extend(
                item for item in declaration.assumptions if item not in threat_model.assumptions
            )
        graph.metadata["threat_model_version"] = threat_model.version
        graph.metadata["technique_catalog_version"] = TECHNIQUE_CATALOG_VERSION
        graph.metadata["hypothesis_count"] = len(threat_model.hypotheses)
        graph_fingerprint = graph.content_fingerprint()
        graph.metadata["graph_fingerprint"] = graph_fingerprint
        graph.metadata["fingerprint"] = graph_fingerprint
        model_fingerprint = _model_fingerprint(
            graph_fingerprint=graph_fingerprint,
            threat_model=threat_model.to_dict(),
            declaration=declaration,
        )
        graph.metadata["model_fingerprint"] = model_fingerprint

        graph_dict = graph.to_dict()
        threat_dict = threat_model.to_dict()
        graph_dict["visualization"] = graph.to_visualization(threat_dict)
        graph_diff = None
        threat_diff = None
        change_analysis = _empty_change_analysis()
        previous_snapshot = None
        projection_version_changed = False
        if previous:
            previous_graph_data = previous.get("graph") or previous.get("runtime_surface_graph") or {}
            previous_threat = previous.get("threat_model") or {}
            previous_projection_version = str(
                previous_graph_data.get("metadata", {}).get("version", "")
            )
            current_projection_version = str(graph.metadata.get("version", ""))
            projection_version_changed = bool(
                previous_projection_version and previous_projection_version != current_projection_version
            )
            if previous_graph_data and not projection_version_changed:
                previous_graph = RuntimeSurfaceGraph.from_dict(previous_graph_data)
                graph_diff = graph.diff(previous_graph)
                change_analysis = analyze_graph_changes(graph_dict, previous_graph_data)
            if previous_threat and not projection_version_changed:
                threat_diff = compare_threat_models(threat_dict, previous_threat)
            previous_snapshot = previous.get("snapshot")

        quality = _quality_report(graph_dict, threat_dict, surface.metadata, declaration_application)
        if invalidated_observation_count:
            quality["diagnostics"].append({
                "level": "warning",
                "code": "stale_observations_invalidated",
                "count": invalidated_observation_count,
            })
            if quality["status"] == "complete":
                quality["status"] = "degraded"
        if previous_load_error:
            quality["diagnostics"].append({
                "level": "warning",
                "code": "invalid_previous_snapshot",
                "message": previous_load_error,
            })
            if quality["status"] == "complete":
                quality["status"] = "degraded"
        if projection_version_changed:
            quality["diagnostics"].append({
                "level": "warning",
                "code": "runtime_projection_version_changed",
                "message": "The previous graph uses a different runtime projection identity scheme; security diffs require a new baseline.",
            })
            if quality["status"] == "complete":
                quality["status"] = "degraded"
        result = {
            "schema": "vibe-sec.vrtm.result.v1",
            "method": "VRTM",
            "method_version": VRTM_METHOD_VERSION,
            "technique_catalog_version": TECHNIQUE_CATALOG_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "project_path": str(self.project_path),
            "model_id": model_fingerprint[:16],
            "graph_fingerprint": graph_fingerprint,
            "model_fingerprint": model_fingerprint,
            "status": quality["status"],
            "surface_summary": surface.get_summary(),
            "graph": graph_dict,
            "threat_model": threat_dict,
            "graph_diff": graph_diff,
            "threat_model_diff": threat_diff,
            "security_change_analysis": change_analysis,
            "declaration_application": declaration_application,
            "observation_application": observation_application,
            "retest_observation_application": retest_observation_application,
            "evidence_continuity": {
                "base_fingerprint": base_fingerprint,
                "carried_observation_count": len(previous_observations),
                "incoming_observation_count": len(incoming_observations),
                "retest_observation_count": len(trusted_finding_values),
                "external_observation_count": len(external_observations),
                "trusted_observation_count": len(harness_observations),
                "invalidated_observation_count": invalidated_observation_count,
            },
            "quality": quality,
            "previous_snapshot": previous_snapshot,
        }
        if retest_diagnostics:
            result["quality"]["diagnostics"].extend(retest_diagnostics)
            if result["quality"]["status"] == "complete":
                result["quality"]["status"] = "degraded"
                result["status"] = "degraded"
        result["persistence"] = {
            "requested": persist,
            "status": "disabled" if not persist else "skipped_invalid" if quality["status"] == "invalid" else "pending",
        }
        if persist and quality["status"] != "invalid":
            result["persistence"] = {"requested": True, "status": "stored"}
            result["snapshot"] = self.store.save(result)
        return result


def _quality_report(
    graph: Dict[str, Any],
    threat_model: Dict[str, Any],
    surface_metadata: Dict[str, Any],
    declaration_application: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    nodes = list(graph.get("nodes", []))
    edges = list(graph.get("edges", []))
    node_ids = [str(item.get("id")) for item in nodes]
    node_id_set = set(node_ids)
    dangling_edges = [
        item for item in edges
        if item.get("source") not in node_id_set or item.get("target") not in node_id_set
    ]
    coverage = dict(graph.get("metadata", {}).get("coverage", {}))
    extraction = dict(surface_metadata.get("extraction_coverage", {}) or {})
    parse_failures = list(extraction.get("parse_failures", []) or [])
    diagnostics = []
    if len(node_ids) != len(node_id_set):
        diagnostics.append({"level": "error", "code": "duplicate_node_ids"})
    if dangling_edges:
        diagnostics.append({"level": "error", "code": "dangling_edges", "count": len(dangling_edges)})
    if parse_failures:
        diagnostics.append({"level": "warning", "code": "parse_failures", "count": len(parse_failures)})
    files_considered = int(extraction.get("files_considered", 0) or 0)
    files_parsed = int(extraction.get("files_parsed", 0) or 0)
    meaningful_nodes = [
        item for item in nodes
        if str(item.get("evidence", {}).get("level", "unknown")) in {
            "declared", "static_observed", "runtime_observed", "verified",
        }
    ]
    if files_considered == 0:
        diagnostics.append({"level": "warning", "code": "zero_extraction_coverage"})
    elif files_parsed == 0:
        diagnostics.append({"level": "warning", "code": "unsupported_extraction_coverage"})
    if not meaningful_nodes:
        diagnostics.append({"level": "warning", "code": "no_meaningful_modeled_entities"})
    if coverage.get("unknown_count", 0):
        diagnostics.append({
            "level": "warning", "code": "unresolved_security_facts",
            "count": coverage.get("unknown_count", 0),
        })
    if declaration_application:
        diagnostics.extend(declaration_application.get("diagnostics", []))
    status = "invalid" if any(item.get("level") == "error" for item in diagnostics) else (
        "degraded" if diagnostics else "complete"
    )
    return {
        "schema": "vibe-sec.vrtm.quality.v1",
        "status": status,
        "graph_integrity": {
            "valid": not dangling_edges and len(node_ids) == len(node_id_set),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "dangling_edge_count": len(dangling_edges),
        },
        "coverage": coverage,
        "extraction_coverage": extraction,
        "hypothesis_count": len(threat_model.get("hypotheses", [])),
        "meaningful_node_count": len(meaningful_nodes),
        "diagnostics": diagnostics,
        "claim_boundary": (
            "Coverage describes modeled evidence and unknowns; it is not a security score or proof of safety."
        ),
    }


def _empty_change_analysis() -> Dict[str, Any]:
    return {
        "schema": "vibe-sec.vrtm.security-change-analysis.v1",
        "authority_expansion": [],
        "new_boundary_crossings": [],
        "new_privileged_asset_ids": [],
        "control_regressions": [],
        "control_improvements": [],
        "security_attribute_changes": [],
        "reason_codes": [],
        "requires_security_review": False,
        "review_reasons": [],
    }


def _stored_observations(graph: Dict[str, Any]) -> list[Dict[str, Any]]:
    values: Dict[str, Dict[str, Any]] = {}
    for target in [*graph.get("nodes", []), *graph.get("edges", [])]:
        for observation in target.get("attributes", {}).get("observations", []) or []:
            if isinstance(observation, dict) and observation.get("id"):
                values[str(observation["id"])] = dict(observation)
    return list(values.values())


def _classify_observations(
    observations: Optional[Iterable[Dict[str, Any]]], trust_class: str,
) -> list[Dict[str, Any]]:
    values = []
    for raw in observations or []:
        if not isinstance(raw, dict):
            values.append(raw)
            continue
        item = dict(raw)
        item["trust_class"] = trust_class
        values.append(item)
    return values


def _model_fingerprint(
    *, graph_fingerprint: str, threat_model: Dict[str, Any], declaration: Optional[VRTMDeclaration],
) -> str:
    payload = {
        "graph_fingerprint": graph_fingerprint,
        "declaration_scope": declaration.scope if declaration else {},
        "assumptions": list(threat_model.get("assumptions", []) or []),
        "exclusions": declaration.exclusions if declaration else [],
        "declaration_digest": declaration.content_digest() if declaration else None,
        "method_version": VRTM_METHOD_VERSION,
        "technique_catalog_version": TECHNIQUE_CATALOG_VERSION,
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    return sha256(encoded).hexdigest()
