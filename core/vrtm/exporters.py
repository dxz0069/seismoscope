"""Human- and machine-readable VRTM exports."""

from __future__ import annotations

import json
from typing import Any


def export_vrtm(result: dict[str, Any], format_type: str) -> str:
    if format_type == "json":
        return json.dumps(result, ensure_ascii=False, indent=2, default=str)
    if format_type == "markdown":
        return _markdown(result)
    if format_type == "dot":
        return _dot(result)
    if format_type == "mermaid":
        return _mermaid(result)
    raise ValueError(f"unsupported VRTM export format: {format_type}")


def _markdown(result: dict[str, Any]) -> str:
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


def _dot(result: dict[str, Any]) -> str:
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


_PLANE_COLORS = {
    "data": "#0284c7",
    "instruction": "#7c3aed",
    "permission": "#d97706",
    "artifact": "#059669",
}


def _mermaid(result: dict[str, Any]) -> str:
    """GitHub 原生可渲染的 Mermaid flowchart（```mermaid 代码块内）。

    节点按类型着色，出现在任一假设攻击路径上的节点以红框标红；
    边标注语义关系与流平面。
    """
    graph = result.get("graph", {})
    hypotheses = result.get("threat_model", {}).get("hypotheses", [])
    risky_nodes = {
        node_id for item in hypotheses for node_id in item.get("attack_path", [])
    }
    lines = ["flowchart LR"]

    node_index = {
        node.get("id", ""): f"n{index}"
        for index, node in enumerate(graph.get("nodes", []))
    }

    def safe(node_id: str) -> str:
        return node_index.get(node_id, "n_unknown")

    for node in graph.get("nodes", []):
        mid = node_index.get(node.get("id", ""), "n_unknown")
        label = _mermaid_label(f"{node.get('label', '')} [{node.get('type', '')}]")
        color = _PLANE_COLORS.get(str(node.get("flow_plane", "")).lower(), "#475569")
        stroke = '#dc2626,"3px"' if node.get("id") in risky_nodes else f'{color},"1.5px"'
        lines.append(f'    {mid}["{label}"]:::plain -.-> style {mid} stroke:{stroke}')
    for edge in graph.get("edges", []):
        source = node_index.get(edge.get("source", ""), safe(edge.get("source", "")))
        target = node_index.get(edge.get("target", ""), safe(edge.get("target", "")))
        relation = _mermaid_label(edge.get("semantic_relation") or edge.get("relation", ""))
        planes = ",".join(edge.get("flow_planes", []))
        label = f"{relation} <small>{planes}</small>" if planes else relation
        lines.append(f'    {source} -->|"{label}"| {target}')
    lines.append("    classDef plain fill:#f8fafc,color:#0f172a;")
    return "\n".join(lines)


def _mermaid_label(value: Any) -> str:
    text = str(value).replace('"', "'").replace("\n", " ").strip()
    return text[:48] + ("…" if len(text) > 48 else "")
