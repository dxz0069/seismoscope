"""Durable project-tree snapshots for post-remediation scope checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable


IGNORED_PARTS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist",
    "build", "coverage", ".next", ".nuxt",
}


def build_tree_snapshot(project_root: str, *, max_files: int = 20_000) -> Dict[str, Any]:
    root = Path(project_root).resolve()
    if not root.is_dir():
        raise ValueError("project_root must be an existing directory")
    files: Dict[str, Dict[str, Any]] = {}
    truncated = False
    for target in _iter_files(root):
        if len(files) >= max(1, int(max_files)):
            truncated = True
            break
        relative = target.relative_to(root).as_posix()
        files[relative] = {
            "sha256": _file_sha256(target),
            "size_bytes": target.stat().st_size,
        }
    tree_digest = _tree_digest(files)
    return {
        "schema": "vibe-sec.tree-snapshot",
        "schema_version": "1.0",
        "hash_algorithm": "sha256",
        "file_count": len(files),
        "truncated": truncated,
        "tree_digest": tree_digest,
        "files": files,
    }


def load_snapshot_ref(snapshot_ref: Dict[str, Any]) -> Dict[str, Any]:
    path = Path(str(snapshot_ref.get("path", ""))).resolve()
    expected = str(snapshot_ref.get("sha256", ""))
    if not path.is_file():
        raise FileNotFoundError(f"Tree snapshot artifact is unavailable: {path}")
    content = path.read_bytes()
    actual = hashlib.sha256(content).hexdigest()
    if not expected or actual != expected:
        raise ValueError("Tree snapshot artifact hash does not match its reference")
    payload = json.loads(content)
    if not isinstance(payload, dict) or payload.get("schema") != "vibe-sec.tree-snapshot":
        raise ValueError("Tree snapshot artifact has an unsupported schema")
    files = payload.get("files")
    if not isinstance(files, dict) or payload.get("tree_digest") != _tree_digest(files):
        raise ValueError("Tree snapshot content digest is invalid")
    if payload.get("truncated") is True:
        raise ValueError("Tree snapshot is truncated and cannot prove changed-tree scope")
    return payload


def diff_tree_snapshot(project_root: str, snapshot: Dict[str, Any]) -> Dict[str, Any]:
    current = build_tree_snapshot(project_root, max_files=max(20_000, int(snapshot.get("file_count", 0)) + 1))
    if current.get("truncated"):
        raise ValueError("Current project tree exceeds the snapshot comparison budget")
    before = dict(snapshot.get("files") or {})
    after = dict(current.get("files") or {})
    added = sorted(set(after) - set(before))
    deleted = sorted(set(before) - set(after))
    modified = sorted(
        path for path in set(before) & set(after)
        if before[path].get("sha256") != after[path].get("sha256")
    )
    return {
        "changed_files": sorted([*added, *modified, *deleted]),
        "added_files": added,
        "modified_files": modified,
        "deleted_files": deleted,
        "baseline_tree_digest": snapshot.get("tree_digest"),
        "current_tree_digest": current.get("tree_digest"),
    }


def _iter_files(root: Path) -> Iterable[Path]:
    for target in root.rglob("*"):
        if not target.is_file() or any(part in IGNORED_PARTS for part in target.relative_to(root).parts):
            continue
        resolved = target.resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        yield resolved


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_digest(files: Dict[str, Any]) -> str:
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
