"""Bounded semantic source analysis for cross-file Python audit paths."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SOURCE_NAME_MARKERS = {
    "request", "req", "user_input", "user_data", "query", "payload", "event",
    "message", "url", "filename", "path", "command", "cmd",
}
GUARD_MARKERS = (
    "allowlist", "authorize", "check_access", "check_permission", "confirm", "escape",
    "permission", "policy", "require_approval", "sanitize", "validate", "verify",
)
SINKS = {
    "eval": "code_execution",
    "exec": "code_execution",
    "os.system": "command_execution",
    "subprocess.call": "command_execution",
    "subprocess.Popen": "command_execution",
    "subprocess.run": "command_execution",
    "cursor.execute": "sql_execution",
    "db.execute": "sql_execution",
    "session.execute": "sql_execution",
    "query": "sql_execution",
    "raw": "sql_execution",
    "open": "file_access",
    "Path.read_bytes": "file_access",
    "Path.read_text": "file_access",
    "Path.write_bytes": "file_access",
    "Path.write_text": "file_access",
    "requests.get": "network_request",
    "requests.post": "network_request",
    "httpx.get": "network_request",
    "httpx.post": "network_request",
    "urllib.request.urlopen": "network_request",
    "pickle.load": "deserialization",
    "pickle.loads": "deserialization",
    "yaml.load": "deserialization",
}


@dataclass
class FunctionRecord:
    record_id: str
    name: str
    qualified_name: str
    file_path: str
    line_start: int
    line_end: int
    parameters: list[str] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    sinks: list[dict[str, Any]] = field(default_factory=list)
    guards: list[dict[str, Any]] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.record_id,
            "name": self.name,
            "qualified_name": self.qualified_name,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "parameters": self.parameters,
            "sources": self.sources,
            "sinks": self.sinks,
            "guards": self.guards,
        }


@dataclass
class PythonSemanticIndex:
    records: list[FunctionRecord]
    files_indexed: int
    parse_errors: list[dict[str, str]] = field(default_factory=list)
    truncated: bool = False

    def __post_init__(self) -> None:
        self.by_id = {record.record_id: record for record in self.records}
        self.by_simple_name: dict[str, list[FunctionRecord]] = {}
        for record in self.records:
            self.by_simple_name.setdefault(record.name, []).append(record)

    def resolve_call(self, call_name: str) -> list[FunctionRecord]:
        return self.by_simple_name.get(call_name.rsplit(".", 1)[-1], [])[:8]


def build_python_semantic_index(
    project_root: Path,
    source_files: Iterable[Path],
    *,
    max_files: int = 2_000,
    max_file_bytes: int = 512_000,
) -> PythonSemanticIndex:
    records: list[FunctionRecord] = []
    parse_errors: list[dict[str, str]] = []
    files_indexed = 0
    truncated = False
    for target in source_files:
        if target.suffix.lower() != ".py" or target.stat().st_size > max_file_bytes:
            continue
        if files_indexed >= max_files:
            truncated = True
            break
        files_indexed += 1
        relative = target.resolve().relative_to(project_root).as_posix()
        content = target.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(content)
        except SyntaxError as exc:
            parse_errors.append({"file_path": relative, "error": str(exc)})
            continue
        records.extend(_records_for_module(relative, tree))
    return PythonSemanticIndex(records, files_indexed, parse_errors[:100], truncated)


def trace_python_flow(
    index: PythonSemanticIndex,
    *,
    file_path: str,
    symbol: str = "",
    line: int = 0,
    max_depth: int = 4,
    max_paths: int = 40,
) -> dict[str, Any]:
    normalized = file_path.replace("\\", "/")
    seeds = [record for record in index.records if record.file_path == normalized]
    if symbol:
        seeds = [
            record for record in seeds
            if record.name == symbol or record.qualified_name.endswith(f".{symbol}")
        ]
    if line > 0:
        containing = [record for record in seeds if record.line_start <= line <= record.line_end]
        seeds = containing or seeds
    seeds = seeds[:20]

    seed_names = {record.name for record in seeds}
    callers = [
        record for record in index.records
        if record.record_id not in {seed.record_id for seed in seeds}
        and any(call["name"].rsplit(".", 1)[-1] in seed_names for call in record.calls)
    ][:100]
    direct_callees = _unique_records(
        target
        for seed in seeds
        for call in seed.calls
        for target in index.resolve_call(call["name"])
    )[:100]

    paths: list[dict[str, Any]] = []
    unresolved = set()
    for seed in seeds:
        queue: list[tuple[FunctionRecord, list[FunctionRecord], list[dict[str, Any]], int]] = [
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
                if not targets and call["name"].rsplit(".", 1)[-1] not in SINKS:
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
        "file_path": normalized,
        "symbol": symbol or None,
        "line": line or None,
        "seed_functions": [record.summary() for record in seeds],
        "callers": [record.summary() for record in callers],
        "callees": [record.summary() for record in direct_callees],
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


def _records_for_module(file_path: str, tree: ast.Module) -> list[FunctionRecord]:
    records: list[FunctionRecord] = []
    module = ".".join(Path(file_path).with_suffix("").parts)

    def visit(nodes: Iterable[ast.stmt], prefix: str = "") -> None:
        for node in nodes:
            if isinstance(node, ast.ClassDef):
                visit(node.body, f"{prefix}{node.name}.")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = f"{module}.{prefix}{node.name}".strip(".")
                records.append(_function_record(file_path, qualified, node))
                visit(node.body, f"{prefix}{node.name}.")

    visit(tree.body)
    return records


def _function_record(
    file_path: str,
    qualified_name: str,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> FunctionRecord:
    calls = []
    guards = []
    sources = []
    sinks = []
    parameters = [argument.arg for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]]
    for parameter in parameters:
        if parameter.lower() in SOURCE_NAME_MARKERS:
            sources.append({"kind": "parameter", "name": parameter, "line": node.lineno})
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _call_name(child.func)
            if not name:
                continue
            observation = {"name": name, "line": int(getattr(child, "lineno", node.lineno))}
            calls.append(observation)
            sink_kind = _sink_kind(name)
            if sink_kind:
                sinks.append({**observation, "kind": sink_kind})
            if any(marker in name.lower() for marker in GUARD_MARKERS):
                guards.append({**observation, "kind": "guard_call"})
            if name in {"input", "sys.stdin.read", "sys.stdin.readline"}:
                sources.append({**observation, "kind": "input_call"})
        elif isinstance(child, ast.Attribute):
            name = _call_name(child)
            if name.startswith(("request.", "flask.request.")):
                sources.append({"kind": "request_access", "name": name, "line": child.lineno})
    return FunctionRecord(
        record_id=f"{file_path}:{node.lineno}:{qualified_name}",
        name=node.name,
        qualified_name=qualified_name,
        file_path=file_path,
        line_start=int(node.lineno),
        line_end=int(getattr(node, "end_lineno", node.lineno)),
        parameters=parameters,
        calls=_dedupe_observations(calls),
        sources=_dedupe_observations(sources),
        sinks=_dedupe_observations(sinks),
        guards=_dedupe_observations(guards),
    )


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _sink_kind(call_name: str) -> str | None:
    if call_name in SINKS:
        return SINKS[call_name]
    simple = call_name.rsplit(".", 1)[-1]
    if simple in {"execute", "executemany", "raw"}:
        return "sql_execution"
    return None


def _unique_records(records: Iterable[FunctionRecord]) -> list[FunctionRecord]:
    result = []
    seen = set()
    for record in records:
        if record.record_id in seen:
            continue
        seen.add(record.record_id)
        result.append(record)
    return result


def _dedupe_observations(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for item in items:
        marker = tuple(sorted(item.items()))
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result
