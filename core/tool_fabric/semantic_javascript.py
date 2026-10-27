"""Bounded Esprima-based semantic flow analysis for JavaScript and JSX."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    import esprima
except ImportError:  # pragma: no cover - dependency failures are reported by the tool.
    esprima = None

from .semantic_source import GUARD_MARKERS, SOURCE_NAME_MARKERS, FunctionRecord

JAVASCRIPT_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs"}

JS_SINKS = {
    "eval": "code_execution",
    "Function": "code_execution",
    "child_process.exec": "command_execution",
    "child_process.execSync": "command_execution",
    "child_process.spawn": "command_execution",
    "child_process.spawnSync": "command_execution",
    "exec": "command_execution",
    "execSync": "command_execution",
    "spawn": "command_execution",
    "db.query": "sql_execution",
    "db.execute": "sql_execution",
    "connection.query": "sql_execution",
    "connection.execute": "sql_execution",
    "pool.query": "sql_execution",
    "pool.execute": "sql_execution",
    "fetch": "network_request",
    "axios": "network_request",
    "axios.get": "network_request",
    "axios.post": "network_request",
    "http.request": "network_request",
    "https.request": "network_request",
    "fs.readFile": "file_access",
    "fs.readFileSync": "file_access",
    "fs.writeFile": "file_access",
    "fs.writeFileSync": "file_access",
    "JSON.parse": "deserialization",
}


@dataclass
class JavaScriptSemanticIndex:
    records: List[FunctionRecord]
    files_indexed: int
    parse_errors: List[Dict[str, str]] = field(default_factory=list)
    truncated: bool = False

    def __post_init__(self) -> None:
        self.by_id = {record.record_id: record for record in self.records}
        self.by_simple_name: Dict[str, List[FunctionRecord]] = {}
        for record in self.records:
            self.by_simple_name.setdefault(record.name, []).append(record)

    def resolve_call(self, call_name: str) -> List[FunctionRecord]:
        return self.by_simple_name.get(call_name.rsplit(".", 1)[-1], [])[:8]


def build_javascript_semantic_index(
    project_root: Path,
    source_files: Iterable[Path],
    *,
    max_files: int = 2_000,
    max_file_bytes: int = 512_000,
) -> JavaScriptSemanticIndex:
    if esprima is None:
        return JavaScriptSemanticIndex([], 0, [{"file_path": "", "error": "esprima is unavailable"}])
    records: List[FunctionRecord] = []
    parse_errors: List[Dict[str, str]] = []
    files_indexed = 0
    truncated = False
    for target in source_files:
        if target.suffix.lower() not in JAVASCRIPT_EXTENSIONS or target.stat().st_size > max_file_bytes:
            continue
        if files_indexed >= max_files:
            truncated = True
            break
        files_indexed += 1
        relative = target.resolve().relative_to(project_root).as_posix()
        content = target.read_text(encoding="utf-8", errors="replace")
        try:
            tree = esprima.parseModule(content, {"loc": True, "tolerant": True, "jsx": True}).toDict()
        except Exception as exc:  # Esprima exposes multiple parser exception classes.
            parse_errors.append({"file_path": relative, "error": str(exc)[:500]})
            continue
        records.extend(_records_for_program(relative, tree))
    return JavaScriptSemanticIndex(records, files_indexed, parse_errors[:100], truncated)


def trace_javascript_flow(
    index: JavaScriptSemanticIndex,
    *,
    file_path: str,
    symbol: str = "",
    line: int = 0,
    max_depth: int = 4,
    max_paths: int = 40,
) -> Dict[str, Any]:
    normalized = file_path.replace("\\", "/")
    seeds = [record for record in index.records if record.file_path == normalized]
    if symbol:
        seeds = [record for record in seeds if record.name == symbol or record.qualified_name.endswith(f".{symbol}")]
    if line > 0:
        containing = [record for record in seeds if record.line_start <= line <= record.line_end]
        seeds = containing or seeds
    seeds = seeds[:20]
    seed_ids = {item.record_id for item in seeds}
    seed_names = {item.name for item in seeds}
    callers = [
        record for record in index.records
        if record.record_id not in seed_ids
        and any(call["name"].rsplit(".", 1)[-1] in seed_names for call in record.calls)
    ][:100]
    callees = _unique_records(
        target for seed in seeds for call in seed.calls for target in index.resolve_call(call["name"])
    )[:100]

    paths: List[Dict[str, Any]] = []
    unresolved = set()
    for seed in seeds:
        queue: List[tuple[FunctionRecord, List[FunctionRecord], List[Dict[str, Any]], int]] = [
            (seed, [seed], [], 0)
        ]
        while queue and len(paths) < max_paths:
            current, nodes, edges, depth = queue.pop(0)
            if current.sinks:
                paths.append({
                    "node_ids": [node.record_id for node in nodes],
                    "nodes": [node.summary() for node in nodes],
                    "edges": edges,
                    "source_observations": [item for node in nodes for item in node.sources],
                    "sink_observations": current.sinks,
                    "guard_observations": [item for node in nodes for item in node.guards],
                    "cross_file": len({node.file_path for node in nodes}) > 1,
                })
            if depth >= max_depth:
                continue
            for call in current.calls:
                targets = index.resolve_call(call["name"])
                if not targets and _js_sink_kind(call["name"]) is None:
                    unresolved.add(call["name"])
                for target in targets:
                    if any(node.record_id == target.record_id for node in nodes):
                        continue
                    queue.append((
                        target,
                        [*nodes, target],
                        [*edges, {
                            "caller_id": current.record_id,
                            "callee_id": target.record_id,
                            "call_name": call["name"],
                            "file_path": current.file_path,
                            "line": call["line"],
                        }],
                        depth + 1,
                    ))
    return {
        "language": "javascript",
        "parser": "esprima",
        "file_path": normalized,
        "symbol": symbol or None,
        "line": line or None,
        "seed_functions": [record.summary() for record in seeds],
        "callers": [record.summary() for record in callers],
        "callees": [record.summary() for record in callees],
        "paths": paths,
        "unresolved_calls": sorted(unresolved)[:200],
        "coverage": {
            "files_indexed": index.files_indexed,
            "functions_indexed": len(index.records),
            "parse_errors": index.parse_errors,
            "index_truncated": index.truncated,
            "max_depth": max_depth,
            "path_count": len(paths),
            "cross_file_path_count": sum(1 for path in paths if path["cross_file"]),
        },
    }


def _records_for_program(file_path: str, tree: Dict[str, Any]) -> List[FunctionRecord]:
    records = []
    module = ".".join(Path(file_path).with_suffix("").parts)
    for node in _walk_nodes(tree):
        node_type = node.get("type")
        name = ""
        function = None
        if node_type == "FunctionDeclaration":
            name = str((node.get("id") or {}).get("name", ""))
            function = node
        elif node_type == "VariableDeclarator" and (node.get("init") or {}).get("type") in {
            "ArrowFunctionExpression", "FunctionExpression",
        }:
            name = str((node.get("id") or {}).get("name", ""))
            function = node.get("init")
        elif node_type == "MethodDefinition" and (node.get("value") or {}).get("type") in {
            "FunctionExpression", "ArrowFunctionExpression",
        }:
            name = _property_name(node.get("key") or {})
            function = node.get("value")
        elif node_type == "Property" and (node.get("value") or {}).get("type") in {
            "FunctionExpression", "ArrowFunctionExpression",
        }:
            name = _property_name(node.get("key") or {})
            function = node.get("value")
        if name and isinstance(function, dict):
            records.append(_function_record(file_path, f"{module}.{name}", name, function))
    return _unique_records(records)


def _function_record(
    file_path: str,
    qualified_name: str,
    name: str,
    node: Dict[str, Any],
) -> FunctionRecord:
    calls = []
    sources = []
    sinks = []
    guards = []
    parameters = [_parameter_name(item) for item in list(node.get("params", []) or [])]
    parameters = [item for item in parameters if item]
    line_start = _line(node)
    line_end = int((((node.get("loc") or {}).get("end") or {}).get("line") or line_start))
    for parameter in parameters:
        if parameter.lower() in SOURCE_NAME_MARKERS:
            sources.append({"kind": "parameter", "name": parameter, "line": line_start})
    for child in _walk_nodes(node.get("body") or {}):
        child_type = child.get("type")
        if child_type in {"CallExpression", "NewExpression"}:
            call_name = _expression_name(child.get("callee") or {})
            if not call_name:
                continue
            observation = {"name": call_name, "line": _line(child)}
            calls.append(observation)
            sink_kind = _js_sink_kind(call_name)
            if sink_kind:
                sinks.append({**observation, "kind": sink_kind})
            if any(marker in call_name.lower() for marker in GUARD_MARKERS):
                guards.append({**observation, "kind": "guard_call"})
        elif child_type == "MemberExpression":
            member = _expression_name(child)
            lowered = member.lower()
            if lowered.startswith(("req.", "request.", "event.", "message.", "location.", "document.", "process.argv")):
                sources.append({"kind": "external_access", "name": member, "line": _line(child)})
        elif child_type == "AssignmentExpression":
            target = _expression_name(child.get("left") or {})
            if target.rsplit(".", 1)[-1] in {"innerHTML", "outerHTML"}:
                sinks.append({"name": target, "line": _line(child), "kind": "html_injection"})
    return FunctionRecord(
        record_id=f"{file_path}:{line_start}:{qualified_name}",
        name=name,
        qualified_name=qualified_name,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        parameters=parameters,
        calls=_dedupe(calls),
        sources=_dedupe(sources),
        sinks=_dedupe(sinks),
        guards=_dedupe(guards),
    )


def _walk_nodes(value: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(value, dict):
        if value.get("type"):
            yield value
        for key, nested in value.items():
            if key != "loc":
                yield from _walk_nodes(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_nodes(nested)


def _expression_name(node: Dict[str, Any]) -> str:
    node_type = node.get("type")
    if node_type == "Identifier":
        return str(node.get("name", ""))
    if node_type in {"ThisExpression", "Super"}:
        return "this" if node_type == "ThisExpression" else "super"
    if node_type == "Literal":
        return str(node.get("value", ""))
    if node_type == "MemberExpression":
        prefix = _expression_name(node.get("object") or {})
        suffix = _expression_name(node.get("property") or {})
        return f"{prefix}.{suffix}".strip(".")
    return ""


def _property_name(node: Dict[str, Any]) -> str:
    return str(node.get("name", node.get("value", "")) or "")


def _parameter_name(node: Dict[str, Any]) -> str:
    if node.get("type") == "Identifier":
        return str(node.get("name", ""))
    if node.get("type") == "AssignmentPattern":
        return _parameter_name(node.get("left") or {})
    return ""


def _line(node: Dict[str, Any]) -> int:
    return int((((node.get("loc") or {}).get("start") or {}).get("line") or 1))


def _js_sink_kind(call_name: str) -> Optional[str]:
    if call_name in JS_SINKS:
        return JS_SINKS[call_name]
    simple = call_name.rsplit(".", 1)[-1]
    if simple in {"query", "execute"}:
        return "sql_execution"
    return None


def _unique_records(records: Iterable[FunctionRecord]) -> List[FunctionRecord]:
    output = []
    seen = set()
    for record in records:
        if record.record_id not in seen:
            seen.add(record.record_id)
            output.append(record)
    return output


def _dedupe(values: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    output = []
    seen = set()
    for value in values:
        marker = tuple(sorted(value.items()))
        if marker not in seen:
            seen.add(marker)
            output.append(value)
    return output
