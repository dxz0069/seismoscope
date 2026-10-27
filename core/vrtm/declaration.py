"""Validated project declarations for runtime facts unavailable in source code."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml

from ..harness.models import (
    RuntimeSurfaceEdge,
    RuntimeSurfaceGraph,
    RuntimeSurfaceNode,
    stable_id,
)
from ..harness.vrtm import NODE_GROUPS, RELATION_SEMANTICS, EvidenceLevel, enrich_runtime_graph

DECLARATION_SCHEMA = "vibe-sec.vrtm.declaration.v1"
_REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9_.:/-]{1,160}$")


class DeclarationError(ValueError):
    pass


@dataclass
class VRTMDeclaration:
    source_path: str
    scope: dict[str, Any] = field(default_factory=dict)
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    exclusions: list[dict[str, Any]] = field(default_factory=list)

    def content_digest(self) -> str:
        payload = {
            "schema": DECLARATION_SCHEMA,
            "scope": self.scope,
            "nodes": self.nodes,
            "edges": self.edges,
            "assumptions": self.assumptions,
            "exclusions": self.exclusions,
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
        return sha256(encoded).hexdigest()

    @classmethod
    def load(cls, path: str) -> VRTMDeclaration:
        source = Path(path).resolve()
        try:
            value = _strict_yaml_load(source.read_text(encoding="utf-8")) or {}
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise DeclarationError(f"Unable to read VRTM declaration: {exc}") from exc
        if not isinstance(value, dict):
            raise DeclarationError("VRTM declaration root must be an object")
        if value.get("schema") != DECLARATION_SCHEMA:
            raise DeclarationError(f"VRTM declaration schema must be {DECLARATION_SCHEMA}")
        declaration = cls(
            source_path=str(source),
            scope=_object(value.get("scope"), "scope"),
            nodes=_object_list(value.get("nodes"), "nodes"),
            edges=_object_list(value.get("edges"), "edges"),
            assumptions=_string_list(value.get("assumptions"), "assumptions"),
            exclusions=_object_list(value.get("exclusions"), "exclusions"),
        )
        declaration.validate()
        return declaration

    @classmethod
    def discover(cls, project_path: str, explicit_path: str | None = None) -> VRTMDeclaration | None:
        if explicit_path:
            return cls.load(explicit_path)
        root = Path(project_path).resolve()
        for candidate in (root / ".vibe-sec" / "vrtm.yaml", root / "vibe-sec.vrtm.yaml"):
            if candidate.is_file():
                return cls.load(str(candidate))
        return None

    def validate(self) -> None:
        if len(self.nodes) > 10_000 or len(self.edges) > 50_000:
            raise DeclarationError("VRTM declaration exceeds the supported graph size")
        keys: set[str] = set()
        for index, node in enumerate(self.nodes):
            node_type = str(node.get("type", ""))
            label = str(node.get("label", ""))
            key = str(node.get("key") or node.get("id") or "")
            if node_type not in NODE_GROUPS:
                raise DeclarationError(f"nodes[{index}].type is unsupported: {node_type}")
            if not label.strip():
                raise DeclarationError(f"nodes[{index}].label is required")
            if not key or not _REFERENCE_PATTERN.fullmatch(key):
                raise DeclarationError(f"nodes[{index}].key must be a stable reference")
            if key in keys:
                raise DeclarationError(f"duplicate declared node key: {key}")
            keys.add(key)
            confidence = float(node.get("confidence", 0.7))
            if not 0.0 <= confidence <= 1.0:
                raise DeclarationError(f"nodes[{index}].confidence must be between 0 and 1")
            _object(node.get("attributes"), f"nodes[{index}].attributes")
        for index, edge in enumerate(self.edges):
            source = str(edge.get("source", ""))
            target = str(edge.get("target", ""))
            relation = str(edge.get("relation", ""))
            if not source or not target:
                raise DeclarationError(f"edges[{index}] requires source and target")
            if relation not in RELATION_SEMANTICS:
                raise DeclarationError(f"edges[{index}].relation is unsupported: {relation}")
            planes = edge.get("flow_planes", []) or []
            if not isinstance(planes, list) or any(
                item not in {"data", "instruction", "authority", "artifact"} for item in planes
            ):
                raise DeclarationError(f"edges[{index}].flow_planes contains an invalid plane")
            required_planes = {item.value for item in RELATION_SEMANTICS[relation][1]}
            if planes and not required_planes.issubset(set(planes)):
                raise DeclarationError(
                    f"edges[{index}].flow_planes must include canonical planes: "
                    + ", ".join(sorted(required_planes))
                )
            confidence = float(edge.get("confidence", 0.7))
            if not 0.0 <= confidence <= 1.0:
                raise DeclarationError(f"edges[{index}].confidence must be between 0 and 1")
            _object(edge.get("attributes"), f"edges[{index}].attributes")

    def merge_into(self, graph: RuntimeSurfaceGraph) -> dict[str, Any]:
        known_ids = {node.node_id for node in graph.nodes}
        references = {node.node_id: node.node_id for node in graph.nodes}
        added_nodes: list[str] = []
        added_edges: list[str] = []
        diagnostics: list[dict[str, Any]] = []

        for value in self.nodes:
            key = str(value.get("key") or value.get("id"))
            requested_id = str(value.get("id") or "")
            node_id = requested_id if requested_id.startswith("declared-") else stable_id(
                "declared", key, value["type"], value["label"],
            )
            references[key] = node_id
            references[f"declared:{key}"] = node_id
            if node_id in known_ids:
                diagnostics.append({"level": "warning", "code": "duplicate_node", "reference": key})
                continue
            attributes = dict(value.get("attributes") or {})
            attributes.update({
                key: value[key]
                for key in ("trust_zone", "privilege_level", "asset_type", "risk_level")
                if key in value
            })
            attributes["declaration_source"] = self.source_path
            attributes["declaration_key"] = key
            graph.nodes.append(RuntimeSurfaceNode(
                node_id=node_id,
                node_type=str(value["type"]),
                label=str(value["label"]),
                attributes=attributes,
                evidence={
                    "level": EvidenceLevel.DECLARED.value,
                    "confidence": float(value.get("confidence", 0.7)),
                    "source": "project_declaration",
                    "file_path": self.source_path,
                },
            ))
            known_ids.add(node_id)
            added_nodes.append(node_id)

        edge_keys = {(edge.source, edge.target, edge.relation) for edge in graph.edges}
        for index, value in enumerate(self.edges):
            source = references.get(str(value["source"]), str(value["source"]))
            target = references.get(str(value["target"]), str(value["target"]))
            if source not in known_ids or target not in known_ids:
                diagnostics.append({
                    "level": "error",
                    "code": "unresolved_edge_reference",
                    "edge_index": index,
                    "source": value["source"],
                    "target": value["target"],
                })
                continue
            relation = str(value["relation"])
            if (source, target, relation) in edge_keys:
                diagnostics.append({"level": "warning", "code": "duplicate_edge", "edge_index": index})
                continue
            attributes = dict(value.get("attributes") or {})
            attributes["declaration_source"] = self.source_path
            edge = RuntimeSurfaceEdge(
                source=source,
                target=target,
                relation=relation,
                attributes=attributes,
                flow_planes=list(value.get("flow_planes", []) or []),
                evidence={
                    "level": EvidenceLevel.DECLARED.value,
                    "confidence": float(value.get("confidence", 0.7)),
                    "source": "project_declaration",
                    "file_path": self.source_path,
                },
            )
            graph.edges.append(edge)
            edge_keys.add((source, target, relation))
            added_edges.append(stable_id("edge", source, target, relation))

        graph.metadata["declaration"] = {
            "schema": DECLARATION_SCHEMA,
            "source_path": self.source_path,
            "scope": self.scope,
            "assumptions": self.assumptions,
            "exclusions": self.exclusions,
            "digest": self.content_digest(),
            "added_node_count": len(added_nodes),
            "added_edge_count": len(added_edges),
        }
        enrich_runtime_graph(graph)
        graph.metadata["fingerprint"] = graph.content_fingerprint()
        return {
            "status": "partial" if any(item["level"] == "error" for item in diagnostics) else "applied",
            "source_path": self.source_path,
            "added_node_ids": added_nodes,
            "added_edge_ids": added_edges,
            "diagnostics": diagnostics,
        }


def _object(value: Any, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise DeclarationError(f"{field_name} must be an object")
    return dict(value)


def _object_list(value: Any, field_name: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise DeclarationError(f"{field_name} must be a list of objects")
    return [dict(item) for item in value]


def _string_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise DeclarationError(f"{field_name} must be a list of strings")
    return list(value)


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key: {key}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _strict_yaml_load(value: str) -> Any:
    return yaml.load(value, Loader=_UniqueKeyLoader)
