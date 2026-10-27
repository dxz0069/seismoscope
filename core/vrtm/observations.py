"""Translate audit and verification results into evidence-bound graph observations."""

from __future__ import annotations

from collections.abc import Iterable
from hashlib import sha1
from typing import Any

from ..harness.models import RuntimeSurfaceGraph

VULNERABILITY_TECHNIQUES = {
    "prompt_injection": "T-PROMPT-INJECTION",
    "indirect_prompt_injection": "T-INDIRECT-PROMPT-INJECTION",
    "excessive_agency": "T-EXCESSIVE-AGENCY",
    "mcp_insecurity": "T-MCP-AUTHORIZATION",
    "xss": "T-BROWSER-SINK-INJECTION",
    "workflow_insecurity": "T-WORKFLOW-PRIVILEGE",
    "authorization_bypass": "T-UNPROTECTED-ENTRY",
    "broken_access_control": "T-UNPROTECTED-ENTRY",
}

VULNERABILITY_NODE_PREFERENCES = {
    "prompt_injection": {"prompt", "model", "external_content"},
    "indirect_prompt_injection": {"external_content", "prompt", "model"},
    "excessive_agency": {"tool", "mcp_capability", "privileged_asset"},
    "mcp_insecurity": {"mcp_capability", "tool", "trust_boundary"},
    "xss": {"browser_sink", "external_content", "entry_point"},
    "workflow_insecurity": {"workflow", "privileged_asset"},
    "authorization_bypass": {"entry_point", "permission", "trust_boundary"},
    "broken_access_control": {"entry_point", "permission", "trust_boundary"},
    "sql_injection": {"storage_asset", "entry_point", "code_block"},
    "command_injection": {"tool", "code_execution", "code_block"},
    "code_injection": {"code_execution", "code_block", "entry_point"},
    "path_traversal": {"storage_asset", "code_block", "entry_point"},
    "hardcoded_password": {"secret_asset", "code_block"},
}


def observations_from_audit(
    findings: Iterable[dict[str, Any]],
    graph: RuntimeSurfaceGraph,
    threat_model: dict[str, Any],
    *,
    run_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return _from_findings(findings, graph, threat_model, phase="audit", run_id=run_id)


def observations_from_verification(
    findings: Iterable[dict[str, Any]],
    graph: RuntimeSurfaceGraph,
    threat_model: dict[str, Any],
    *,
    run_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return _from_findings(findings, graph, threat_model, phase="verification", run_id=run_id)


def _from_findings(
    findings: Iterable[dict[str, Any]],
    graph: RuntimeSurfaceGraph,
    threat_model: dict[str, Any],
    *,
    phase: str,
    run_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    observations: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for finding in findings:
        finding_id = str(finding.get("id", ""))
        target = _target_node(finding, graph)
        if target is None:
            diagnostics.append({
                "level": "warning",
                "code": "finding_not_linked_to_graph",
                "finding_id": finding_id,
                "file_path": finding.get("file_path"),
            })
            continue
        hypothesis_ids = _hypothesis_ids(finding, target.node_id, threat_model)
        evidence_level, source_tool, evidence_ref = _evidence_binding(finding, phase)
        verification_status = str(finding.get("verification_status", ""))
        verdict = str(finding.get("review_verdict") or finding.get("verdict") or "")
        facts = {
            "finding_id": finding_id,
            "vulnerability_type": finding.get("vulnerability_type"),
            "severity": finding.get("severity"),
            "verdict": verdict,
            "verification_status": verification_status,
            "evidence_gaps": list(finding.get("evidence_gaps", []) or []),
        }
        remediation_status = str(finding.get("remediation_status", "")).strip()
        if remediation_status:
            facts["remediation_status"] = remediation_status
        if evidence_level == "verified":
            facts["verification_predicate"] = str(
                finding.get("verification_predicate") or "Verification pipeline reached a terminal predicate verdict."
            )
        raw_id = "|".join((
            phase,
            str(finding.get("lane", "")),
            finding_id,
            str(finding.get("vulnerability_type", "")),
            target.node_id,
            verification_status,
            verdict,
        ))
        observations.append({
            "id": f"obs-{sha1(raw_id.encode('utf-8')).hexdigest()[:16]}",
            "target_kind": "node",
            "target_id": target.node_id,
            "evidence_level": evidence_level,
            "source_agent": phase,
            "source_tool": source_tool,
            "evidence_ref": evidence_ref,
            "confidence": float(finding.get("confidence", 0.5) or 0.5),
            "facts": facts,
            "hypothesis_ids": hypothesis_ids,
            "trust_class": "harness",
            "provenance": {
                "run_id": run_id,
                "producer": "orchestrator",
                "phase": phase,
                "finding_id": finding_id,
            },
        })
    return observations, diagnostics


def _target_node(finding: dict[str, Any], graph: RuntimeSurfaceGraph) -> Any:
    # A retest is bound to the model that generated the remediation package.
    # Prefer that stable binding when the node survives the post-fix rebuild;
    # otherwise fall back to source provenance rather than inventing a link.
    known_node_ids = [
        str(item) for item in finding.get("surface_node_ids", []) or [] if str(item)
    ]
    for node_id in known_node_ids:
        target = next((node for node in graph.nodes if node.node_id == node_id), None)
        if target is not None:
            return target
    file_path = str(finding.get("file_path", "")).replace("\\", "/")
    line = int(finding.get("line_start", 0) or 0)
    vulnerability_type = str(finding.get("vulnerability_type", ""))
    preferences = VULNERABILITY_NODE_PREFERENCES.get(vulnerability_type, {"code_block", "entry_point"})
    candidates = []
    for node in graph.nodes:
        node_path = str(node.attributes.get("file_path", "")).replace("\\", "/")
        if not file_path or node_path != file_path:
            continue
        start = int(node.attributes.get("line_start", 0) or 0)
        end = int(node.attributes.get("line_end", start) or start)
        contains = bool(line and start <= line <= max(start, end))
        distance = 0 if contains else abs(start - line) if line and start else 100_000
        preferred = 0 if node.node_type in preferences else 1
        candidates.append((preferred, distance, node.node_id, node))
    return min(candidates, default=(None, None, None, None))[3]


def _hypothesis_ids(
    finding: dict[str, Any], target_id: str, threat_model: dict[str, Any],
) -> list[str]:
    known_ids = {
        str(item) for item in finding.get("risk_hypothesis_ids", []) or [] if str(item)
    }
    current_ids = {
        str(item.get("id")) for item in threat_model.get("hypotheses", []) if item.get("id")
    }
    preserved = sorted(known_ids & current_ids)
    if preserved:
        return preserved
    technique_id = VULNERABILITY_TECHNIQUES.get(str(finding.get("vulnerability_type", "")))
    related_node_ids = {
        str(item) for item in finding.get("surface_node_ids", []) or [] if str(item)
    }
    related_node_ids.add(target_id)
    values = []
    for hypothesis in threat_model.get("hypotheses", []):
        if technique_id and hypothesis.get("technique_id") != technique_id:
            continue
        if not related_node_ids.intersection(hypothesis.get("attack_path", []) or []):
            continue
        values.append(str(hypothesis.get("id")))
    return values


def _evidence_binding(finding: dict[str, Any], phase: str) -> tuple[str, str, str]:
    finding_id = str(finding.get("id", "unknown"))
    if phase == "verification" and finding.get("verification_status") in {"verified", "rejected"}:
        return "verified", "verification_pipeline", f"verification-result:{finding_id}"
    evidence = finding.get("evidence_bundle") or finding.get("evidence") or []
    if evidence:
        return "static_observed", "audit_pipeline", f"audit-finding:{finding_id}"
    return "inferred", "", ""
