"""Human- and machine-readable VRTM exports."""

from __future__ import annotations

import json
from typing import Any, Dict


def export_vrtm(result: Dict[str, Any], format_type: str) -> str:
    if format_type == "json":
        return json.dumps(result, ensure_ascii=False, indent=2, default=str)
    if format_type == "markdown":
        return _markdown(result)
    if format_type == "dot":
        return _dot(result)
    raise ValueError(f"unsupported VRTM export format: {format_type}")


def _markdown(result: Dict[str, Any]) -> str:
    graph = result.get("graph", {})
    coverage = graph.get("metadata", {}).get("coverage", {})
    threat = result.get("threat_model", {})
    changes = result.get("security_change_analysis", {})
    lines = [
        "# VRTM Runtime Threat Model",
        "",
        f"- Model: `{result.get('model_id', '')}`",
        f"- Status: `{result.get('status', 'unknown')}`",
        f"- Graph fingerprint: `{result.get('graph_fingerprint', graph.get('metadata', {}).get('fingerprint', ''))}`",
        f"- Model fingerprint: `{result.get('model_fingerprint', '')}`",
        f"- Nodes / edges: {coverage.get('node_count', 0)} / {coverage.get('edge_count', 0)}",
        f"- Risk hypotheses: {len(threat.get('hypotheses', []))}",
        f"- Unknown security facts: {coverage.get('unknown_count', 0)}",
        "",
        "## Flow Planes",
        "",
    ]
    for plane, count in coverage.get("flow_plane_edge_counts", {}).items():
        lines.append(f"- `{plane}`: {count} relations")
    lines.extend(["", "## Risk Hypotheses", ""])
    if not threat.get("hypotheses"):
        lines.append("No risk hypothesis was generated from the current evidence.")
    for item in threat.get("hypotheses", []):
        lines.extend([
            f"### [{str(item.get('severity', 'unknown')).upper()}] {item.get('title', '')}",
            "",
            f"- ID: `{item.get('id', '')}`",
            f"- Technique: `{item.get('technique_id', '')}`",
            f"- Status: `{item.get('status', 'open')}`",
            f"- Confidence: `{item.get('confidence', 0)}`",
            f"- Planes: {', '.join(item.get('flow_planes', []))}",
            f"- Path: {' -> '.join(item.get('attack_path', []))}",
            f"- Impact: {item.get('impact', '')}",
            "",
        ])
        for gap in item.get("control_gaps", []):
            lines.append(
                f"- Control gap `{gap.get('control_type', '')}`: {gap.get('expected_control', '')}"
            )
        lines.append("")
    lines.extend(["## Security-Significant Changes", ""])
    if changes.get("requires_security_review"):
        lines.append("Security review is required: " + ", ".join(changes.get("review_reasons", [])))
    else:
        lines.append("No security-significant expansion was detected against the selected baseline.")
    lines.extend(["", "## Unknowns", ""])
    for item in coverage.get("unknowns", []):
        lines.append(f"- `{item.get('kind', 'unknown')}` at `{item.get('node_id', '')}`")
    lines.extend([
        "",
        "> Coverage and confidence describe available evidence. They do not prove that the project is secure.",
    ])
    return "\n".join(lines)


def _dot(result: Dict[str, Any]) -> str:
    graph = result.get("graph", {})
    hypotheses = result.get("threat_model", {}).get("hypotheses", [])
    risky_nodes = {
        node_id for item in hypotheses for node_id in item.get("attack_path", [])
    }
    lines = ["digraph VRTM {", "  rankdir=LR;", "  graph [fontname=\"Arial\"];", "  node [fontname=\"Arial\"];", "  edge [fontname=\"Arial\"];" ]
    for node in graph.get("nodes", []):
        node_id = _escape(node.get("id", ""))
        label = _escape(f"{node.get('label', '')}\n{node.get('type', '')}")
        color = "#dc2626" if node.get("id") in risky_nodes else "#475569"
        lines.append(f'  "{node_id}" [label="{label}", color="{color}"];')
    for edge in graph.get("edges", []):
        source = _escape(edge.get("source", ""))
        target = _escape(edge.get("target", ""))
        relation = _escape(edge.get("semantic_relation") or edge.get("relation", ""))
        planes = _escape(",".join(edge.get("flow_planes", [])))
        lines.append(f'  "{source}" -> "{target}" [label="{relation}\n{planes}"];')
    lines.append("}")
    return "\n".join(lines)


def _escape(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
