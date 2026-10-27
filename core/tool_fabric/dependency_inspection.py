"""Bounded, provenance-preserving dependency manifest inspection."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

MAX_MANIFEST_BYTES = 2_000_000

_IGNORED = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv", "env",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist", "build",
    ".next", ".nuxt",
}

_KNOWN_NAMES = {
    "pyproject.toml", "poetry.lock", "uv.lock",
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "cargo.toml", "cargo.lock",
}

_LOCK_NAMES = {
    "poetry.lock", "uv.lock", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "go.sum", "gradle.lockfile", "cargo.lock",
}


def inspect_dependencies(
    project_root: Path,
    *,
    ecosystem: str = "",
    max_packages: int = 1_000,
    max_manifests: int = 100,
) -> Dict[str, Any]:
    root = project_root.resolve()
    selected_ecosystem = ecosystem.strip().lower()
    matching_paths = (
        path for path in _manifest_paths(root)
        if not selected_ecosystem or _ecosystem(path.name) == selected_ecosystem
    )
    bounded_paths = []
    for path in matching_paths:
        if len(bounded_paths) > max_manifests:
            break
        bounded_paths.append(path)
    truncated = len(bounded_paths) > max_manifests
    paths = bounded_paths[:max_manifests]
    manifests: List[Dict[str, Any]] = []
    direct: List[Dict[str, Any]] = []
    locked: List[Dict[str, Any]] = []
    gaps: List[str] = []
    for path in paths:
        relative = path.relative_to(root).as_posix()
        detected = _ecosystem(path.name)
        kind = "lockfile" if path.name.lower() in _LOCK_NAMES else "manifest"
        record = {
            "file_path": relative,
            "ecosystem": detected,
            "kind": kind,
            "size_bytes": path.stat().st_size,
            "sha256": _file_sha256(path),
            "status": "parsed",
        }
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            record.update({"status": "skipped", "error": f"file exceeds {MAX_MANIFEST_BYTES} bytes"})
            gaps.append(f"Skipped oversized dependency file: {relative}")
            manifests.append(record)
            continue
        try:
            parsed, parser_gap = _parse_file(path, relative, detected)
            if parser_gap:
                record.update({"status": "recognized_unparsed", "error": parser_gap})
                gaps.append(f"{relative}: {parser_gap}")
            else:
                target = locked if kind == "lockfile" else direct
                target.extend(parsed)
                record["dependency_count"] = len(parsed)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError, ET.ParseError) as exc:
            record.update({"status": "parse_error", "error": str(exc)[:500]})
            gaps.append(f"Could not parse dependency file {relative}: {str(exc)[:200]}")
        manifests.append(record)

    direct = _deduplicate(direct)
    locked = _deduplicate(locked)
    lock_index = {
        (item["ecosystem"], _normalized_name(item["name"], item["ecosystem"])): item["version_spec"]
        for item in locked
        if item.get("name") and item.get("version_spec")
    }
    for item in direct:
        resolved = lock_index.get((item["ecosystem"], _normalized_name(item["name"], item["ecosystem"])))
        if resolved:
            item["resolved_version"] = resolved

    if len(direct) > max_packages:
        direct = direct[:max_packages]
        gaps.append(f"Direct dependency output truncated at {max_packages} packages")
        truncated = True
    if len(locked) > max_packages:
        locked = locked[:max_packages]
        gaps.append(f"Locked dependency output truncated at {max_packages} packages")
        truncated = True

    ecosystems = sorted({item["ecosystem"] for item in manifests})
    lock_coverage = []
    for name in ecosystems:
        ecosystem_manifests = [item for item in manifests if item["ecosystem"] == name and item["kind"] == "manifest"]
        ecosystem_locks = [item for item in manifests if item["ecosystem"] == name and item["kind"] == "lockfile"]
        parsed_locks = [item for item in ecosystem_locks if item["status"] == "parsed"]
        if not ecosystem_manifests:
            status = "lockfile_only"
        elif not ecosystem_locks:
            status = "missing"
            gaps.append(f"No lockfile found for {name} dependency manifest")
        elif not parsed_locks:
            status = "unverifiable"
        else:
            status = "available"
        lock_coverage.append({
            "ecosystem": name,
            "status": status,
            "manifests": [item["file_path"] for item in ecosystem_manifests],
            "lockfiles": [item["file_path"] for item in ecosystem_locks],
        })

    return {
        "ecosystems": ecosystems,
        "manifests": manifests,
        "dependencies": direct,
        "locked_dependencies": locked,
        "dependency_count": len(direct),
        "locked_dependency_count": len(locked),
        "unpinned_direct_count": sum(not item.get("pinned", False) for item in direct),
        "lock_coverage": lock_coverage,
        "coverage": {
            "files_examined": len(manifests),
            "parse_errors": sum(item["status"] == "parse_error" for item in manifests),
            "recognized_unparsed": sum(item["status"] == "recognized_unparsed" for item in manifests),
            "truncated": truncated,
            "gaps": list(dict.fromkeys(gaps)),
        },
    }


def is_dependency_file(path: Path) -> bool:
    name = path.name.lower()
    return name in _KNOWN_NAMES or (name.startswith("requirements") and name.endswith(".txt"))


def _manifest_paths(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in _IGNORED for part in path.relative_to(root).parts):
            continue
        if is_dependency_file(path):
            yield path


def _ecosystem(name: str) -> str:
    lowered = name.lower()
    if lowered.startswith("requirements") or lowered in {"pyproject.toml", "poetry.lock", "uv.lock"}:
        return "python"
    if lowered in {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}:
        return "node"
    if lowered in {"go.mod", "go.sum"}:
        return "go"
    if lowered == "pom.xml":
        return "maven"
    if lowered in {"build.gradle", "build.gradle.kts", "gradle.lockfile"}:
        return "gradle"
    if lowered in {"cargo.toml", "cargo.lock"}:
        return "cargo"
    return "unknown"


def _parse_file(path: Path, relative: str, ecosystem: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    name = path.name.lower()
    text = path.read_text(encoding="utf-8", errors="replace")
    parsers: Dict[str, Callable[[str, str], List[Dict[str, Any]]]] = {
        "pyproject.toml": _parse_pyproject,
        "poetry.lock": _parse_toml_lock,
        "uv.lock": _parse_toml_lock,
        "package.json": _parse_package_json,
        "package-lock.json": _parse_package_lock,
        "npm-shrinkwrap.json": _parse_package_lock,
        "go.mod": _parse_go_mod,
        "go.sum": _parse_go_sum,
        "pom.xml": _parse_pom,
        "build.gradle": _parse_gradle,
        "build.gradle.kts": _parse_gradle,
        "gradle.lockfile": _parse_gradle_lock,
        "cargo.toml": _parse_cargo,
        "cargo.lock": _parse_toml_lock,
    }
    if name.startswith("requirements") and name.endswith(".txt"):
        return _parse_requirements(text, relative), None
    if name in {"yarn.lock", "pnpm-lock.yaml"}:
        return [], "lockfile detected but exact-version parser is not implemented"
    parser = parsers.get(name)
    if not parser:
        return [], "dependency file type is not supported"
    return parser(text, relative), None


def _entry(
    ecosystem: str,
    name: Any,
    version: Any,
    scope: str,
    file_path: str,
    line: int,
    *,
    pinned: Optional[bool] = None,
) -> Dict[str, Any]:
    clean_name = str(name or "").strip()
    clean_version = _safe_version(version)
    return {
        "ecosystem": ecosystem,
        "name": clean_name[:300],
        "version_spec": clean_version[:500],
        "scope": scope,
        "pinned": _is_pinned(clean_version, ecosystem) if pinned is None else pinned,
        "provenance": {"file_path": file_path, "line": max(1, int(line or 1))},
    }


def _safe_version(value: Any) -> str:
    text = str(value if value is not None else "").strip()
    if re.search(r"(?:https?|git\+ssh)://[^/@\s]+:[^/@\s]+@", text, re.IGNORECASE):
        return "direct-url-with-redacted-credentials"
    if re.match(r"^(?:https?|git\+|file:|github:)", text, re.IGNORECASE):
        return "direct-url"
    return text


def _is_pinned(version: str, ecosystem: str) -> bool:
    if not version or version in {"*", "latest"}:
        return False
    if ecosystem == "python":
        return bool(re.fullmatch(r"===?\s*[^,;\s]+", version))
    if ecosystem in {"node", "cargo"}:
        return bool(re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?", version))
    if ecosystem == "maven":
        return "${" not in version and not any(char in version for char in "[,](")
    return bool(re.fullmatch(r"v?\d+(?:\.\d+)*(?:[-+][A-Za-z0-9.-]+)?", version))


def _line_of(text: str, needle: str) -> int:
    for number, line in enumerate(text.splitlines(), 1):
        if needle and needle in line:
            return number
    return 1


def _parse_requirement(value: str) -> Tuple[str, str]:
    item = value.split(";", 1)[0].strip()
    if " @ " in item:
        name, _ = item.split(" @ ", 1)
        return name.strip(), "direct-url"
    match = re.match(r"^([A-Za-z0-9_.-]+(?:\[[^\]]+\])?)\s*(.*)$", item)
    return (match.group(1), match.group(2).strip()) if match else (item, "")


def _parse_requirements(text: str, relative: str) -> List[Dict[str, Any]]:
    values = []
    for line_number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(("-r", "--requirement", "-c", "--constraint")):
            continue
        if stripped.startswith("-e "):
            stripped = stripped[3:].strip()
        name, version = _parse_requirement(stripped)
        if name:
            values.append(_entry("python", name, version, "direct", relative, line_number))
    return values


def _parse_pyproject(text: str, relative: str) -> List[Dict[str, Any]]:
    data = tomllib.loads(text)
    values = []
    project = dict(data.get("project", {}) or {})
    for requirement in list(project.get("dependencies", []) or []):
        name, version = _parse_requirement(str(requirement))
        values.append(_entry("python", name, version, "direct", relative, _line_of(text, str(requirement))))
    for group, requirements in dict(project.get("optional-dependencies", {}) or {}).items():
        for requirement in list(requirements or []):
            name, version = _parse_requirement(str(requirement))
            values.append(_entry("python", name, version, f"optional:{group}", relative, _line_of(text, str(requirement))))
    poetry = dict(dict(data.get("tool", {}) or {}).get("poetry", {}) or {})
    for group, dependencies in (("direct", poetry.get("dependencies", {})), ("dev", poetry.get("dev-dependencies", {}))):
        for name, spec in dict(dependencies or {}).items():
            if str(name).lower() == "python":
                continue
            version = spec.get("version", "") if isinstance(spec, dict) else spec
            values.append(_entry("python", name, version, group, relative, _line_of(text, str(name))))
    return values


def _parse_toml_lock(text: str, relative: str) -> List[Dict[str, Any]]:
    data = tomllib.loads(text)
    ecosystem = "cargo" if Path(relative).name.lower() == "cargo.lock" else "python"
    return [
        _entry(ecosystem, item.get("name"), item.get("version"), "locked", relative, _line_of(text, str(item.get("name", ""))), pinned=True)
        for item in list(data.get("package", []) or [])
        if isinstance(item, dict) and item.get("name")
    ]


def _parse_package_json(text: str, relative: str) -> List[Dict[str, Any]]:
    data = json.loads(text)
    values = []
    groups = {
        "dependencies": "direct", "devDependencies": "dev", "peerDependencies": "peer",
        "optionalDependencies": "optional",
    }
    for key, scope in groups.items():
        for name, version in dict(data.get(key, {}) or {}).items():
            values.append(_entry("node", name, version, scope, relative, _line_of(text, f'"{name}"')))
    return values


def _parse_package_lock(text: str, relative: str) -> List[Dict[str, Any]]:
    data = json.loads(text)
    values = []
    packages = dict(data.get("packages", {}) or {})
    for location, item in packages.items():
        if not location or not isinstance(item, dict) or not item.get("version"):
            continue
        name = item.get("name") or str(location).split("node_modules/")[-1]
        values.append(_entry("node", name, item["version"], "locked", relative, _line_of(text, f'"{location}"'), pinned=True))
    if not packages:
        for name, item in dict(data.get("dependencies", {}) or {}).items():
            if isinstance(item, dict) and item.get("version"):
                values.append(_entry("node", name, item["version"], "locked", relative, _line_of(text, f'"{name}"'), pinned=True))
    return values


def _parse_go_mod(text: str, relative: str) -> List[Dict[str, Any]]:
    values = []
    in_block = False
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("//", 1)[0].strip()
        if line == "require (":
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) >= 2:
            values.append(_entry("go", parts[0], parts[1], "direct", relative, line_number))
    return values


def _parse_go_sum(text: str, relative: str) -> List[Dict[str, Any]]:
    values = []
    for line_number, line in enumerate(text.splitlines(), 1):
        parts = line.split()
        if len(parts) >= 2:
            values.append(_entry("go", parts[0], parts[1].removesuffix("/go.mod"), "locked", relative, line_number, pinned=True))
    return values


def _parse_pom(text: str, relative: str) -> List[Dict[str, Any]]:
    root = ET.fromstring(text)
    properties = {}
    for node in root.iter():
        if _local(node.tag) == "properties":
            properties.update({_local(child.tag): (child.text or "").strip() for child in node})
    values = []
    for dependency in root.iter():
        if _local(dependency.tag) != "dependency":
            continue
        fields = {_local(child.tag): (child.text or "").strip() for child in dependency}
        if not fields.get("artifactId"):
            continue
        version = fields.get("version", "")
        match = re.fullmatch(r"\$\{([^}]+)\}", version)
        if match and match.group(1) in properties:
            version = properties[match.group(1)]
        name = f"{fields.get('groupId', '')}:{fields['artifactId']}".strip(":")
        values.append(_entry("maven", name, version, fields.get("scope", "compile"), relative, _line_of(text, fields["artifactId"])))
    return values


def _parse_gradle(text: str, relative: str) -> List[Dict[str, Any]]:
    pattern = re.compile(
        r"^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s*"
        r"(?:\(\s*)?['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]",
        re.MULTILINE,
    )
    return [
        _entry("gradle", f"{match.group(2)}:{match.group(3)}", match.group(4), match.group(1), relative, text[:match.start()].count("\n") + 1)
        for match in pattern.finditer(text)
    ]


def _parse_gradle_lock(text: str, relative: str) -> List[Dict[str, Any]]:
    values = []
    for line_number, raw in enumerate(text.splitlines(), 1):
        item = raw.split("=", 1)[0].strip()
        parts = item.split(":")
        if len(parts) >= 3 and not item.startswith("#"):
            values.append(_entry("gradle", ":".join(parts[:2]), parts[2], "locked", relative, line_number, pinned=True))
    return values


def _parse_cargo(text: str, relative: str) -> List[Dict[str, Any]]:
    data = tomllib.loads(text)
    values = []
    groups = {"dependencies": "direct", "dev-dependencies": "dev", "build-dependencies": "build"}
    for table, scope in groups.items():
        for name, spec in dict(data.get(table, {}) or {}).items():
            version = spec.get("version", "") if isinstance(spec, dict) else spec
            values.append(_entry("cargo", name, version, scope, relative, _line_of(text, str(name))))
    return values


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _normalized_name(name: str, ecosystem: str) -> str:
    lowered = str(name).lower()
    return re.sub(r"[-_.]+", "-", lowered) if ecosystem == "python" else lowered


def _deduplicate(values: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    output = []
    for item in values:
        key = (
            item.get("ecosystem"), _normalized_name(item.get("name", ""), item.get("ecosystem", "")),
            item.get("version_spec"), item.get("scope"),
            (item.get("provenance") or {}).get("file_path"),
        )
        if key not in seen and item.get("name"):
            seen.add(key)
            output.append(item)
    return output


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
