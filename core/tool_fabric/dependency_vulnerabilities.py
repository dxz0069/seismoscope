"""OSV-backed dependency vulnerability matching with explicit network policy."""

from __future__ import annotations

import asyncio
import inspect
import re
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from .dependency_inspection import inspect_dependencies
from .models import (
    ToolAdapterError,
    ToolExecutionStatus,
    ToolRequest,
    ToolResult,
    ToolRiskClass,
    ToolSignal,
    ToolSpec,
    utc_now,
)

OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_ECOSYSTEMS = {
    "python": "PyPI",
    "node": "npm",
    "go": "Go",
    "maven": "Maven",
    "gradle": "Maven",
    "cargo": "crates.io",
}


class OsvVulnerabilityAdapter:
    spec = ToolSpec(
        name="query_dependency_vulnerabilities",
        description=(
            "Match exact locked project dependency versions against OSV. This performs a fixed-endpoint "
            "network query and returns source-grounded vulnerability signals; unpinned packages are gaps."
        ),
        capability="scanner.dependency_vulnerabilities",
        risk_class=ToolRiskClass.SCANNER,
        required_permissions=["network:api.osv.dev"],
        timeout_seconds=60,
        input_schema={
            "type": "object",
            "properties": {
                "ecosystem": {
                    "type": "string",
                    "enum": ["python", "node", "go", "maven", "gradle", "cargo"],
                },
                "max_packages": {"type": "integer", "minimum": 1, "maximum": 2000},
                "max_vulnerabilities": {"type": "integer", "minimum": 1, "maximum": 5000},
            },
        },
        metadata={
            "network_endpoint": OSV_QUERY_BATCH_URL,
            "database": "OSV",
            "database_freshness": "live_query_without_snapshot_version",
        },
    )

    def __init__(
        self,
        query_batch: Callable[[dict[str, Any]], Awaitable[dict[str, Any]] | dict[str, Any]] | None = None,
    ):
        self._query_batch = query_batch or self._http_query_batch

    async def execute(self, request: ToolRequest, context: Any) -> ToolResult:
        max_packages = _bounded(request.arguments.get("max_packages", 1000), 1, 2000)
        max_vulnerabilities = _bounded(
            request.arguments.get("max_vulnerabilities", 2000), 1, 5000,
        )
        inventory = inspect_dependencies(
            context.project_root,
            ecosystem=str(request.arguments.get("ecosystem", "") or ""),
            max_packages=max_packages,
        )
        packages, gaps = _queryable_packages(inventory, max_packages)
        queried_at = utc_now()
        if not packages:
            output = _base_output(inventory, packages, gaps, queried_at)
            output.update({"vulnerabilities": [], "vulnerability_count": 0})
            artifact = context.artifact_store.put_json(
                output,
                producer=self.spec.name,
                artifact_type="dependency_vulnerability_scan",
                file_name="osv-empty-scan.json",
            )
            output["artifact_ref"] = artifact.artifact_id
            return ToolResult(output=output, artifacts=[artifact])

        try:
            combined_results = []
            for offset in range(0, len(packages), 1000):
                batch = packages[offset:offset + 1000]
                query_payload = {
                    "queries": [
                        {
                            "package": {
                                "name": item["name"],
                                "ecosystem": _OSV_ECOSYSTEMS[item["ecosystem"]],
                            },
                            "version": item["version"],
                        }
                        for item in batch
                    ]
                }
                response = self._query_batch(query_payload)
                response = await response if inspect.isawaitable(response) else response
                if not isinstance(response, dict) or not isinstance(response.get("results"), list):
                    raise ValueError("OSV querybatch response does not contain a results list")
                if len(response["results"]) != len(batch):
                    raise ValueError("OSV querybatch result count does not match package count")
                combined_results.extend(response["results"])
            response = {"results": combined_results}
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            failure = {
                "scanner": "osv",
                "endpoint": OSV_QUERY_BATCH_URL,
                "queried_at": queried_at,
                "package_count": len(packages),
                "status": "failed",
                "error_type": type(exc).__name__,
            }
            artifact = context.artifact_store.put_json(
                failure,
                producer=self.spec.name,
                artifact_type="dependency_vulnerability_scan_failure",
                file_name="osv-scan-failure.json",
            )
            raise ToolAdapterError(
                f"OSV dependency query failed: {exc}",
                status=ToolExecutionStatus.FAILED,
                result=ToolResult(output={**failure, "artifact_ref": artifact.artifact_id}, artifacts=[artifact]),
            ) from exc

        vulnerabilities: list[dict[str, Any]] = []
        for package, result in zip(packages, response["results"], strict=True):
            if not isinstance(result, dict):
                continue
            for vulnerability in list(result.get("vulns", []) or []):
                if not isinstance(vulnerability, dict):
                    continue
                vulnerabilities.append(_normalize_vulnerability(package, vulnerability))
                if len(vulnerabilities) >= max_vulnerabilities:
                    gaps.append(f"Vulnerability output truncated at {max_vulnerabilities} records")
                    break
            if len(vulnerabilities) >= max_vulnerabilities:
                break

        raw_artifact = context.artifact_store.put_json(
            {
                "scanner": "osv",
                "endpoint": OSV_QUERY_BATCH_URL,
                "queried_at": queried_at,
                "query_package_count": len(packages),
                "response": response,
            },
            producer=self.spec.name,
            artifact_type="dependency_vulnerability_raw_response",
            file_name="osv-querybatch-response.json",
        )
        output = _base_output(inventory, packages, gaps, queried_at)
        output.update({
            "vulnerabilities": vulnerabilities,
            "vulnerability_count": len(vulnerabilities),
            "raw_artifact_ref": raw_artifact.artifact_id,
        })
        summary_artifact = context.artifact_store.put_json(
            output,
            producer=self.spec.name,
            artifact_type="dependency_vulnerability_scan",
            file_name="osv-dependency-vulnerabilities.json",
        )
        output["artifact_ref"] = summary_artifact.artifact_id
        signals = [
            ToolSignal(
                kind="dependency_vulnerability",
                summary=(
                    f"{item['id']} affects {item['package']['name']} "
                    f"{item['package']['version']}: {item['summary']}"
                ),
                severity=item["severity"],
                confidence=0.95,
                rule_id=item["id"],
                file_path=item["provenance"]["file_path"],
                line_start=item["provenance"]["line"],
                line_end=item["provenance"]["line"],
                artifact_refs=[raw_artifact.artifact_id, summary_artifact.artifact_id],
                metadata={
                    "scanner": "osv",
                    "package": item["package"],
                    "aliases": item["aliases"],
                    "fixed_versions": item["fixed_versions"],
                    "database_freshness": self.spec.metadata["database_freshness"],
                    "queried_at": queried_at,
                },
            )
            for item in vulnerabilities
        ]
        return ToolResult(output=output, signals=signals, artifacts=[raw_artifact, summary_artifact])

    @staticmethod
    async def _http_query_batch(payload: dict[str, Any]) -> dict[str, Any]:
        timeout = httpx.Timeout(45.0, connect=10.0)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            for attempt in range(3):
                response = await client.post(
                    OSV_QUERY_BATCH_URL,
                    json=payload,
                    headers={"User-Agent": "vibe-sec-platform/0.5"},
                )
                if response.status_code not in {429, 500, 502, 503, 504} or attempt == 2:
                    response.raise_for_status()
                    return response.json()
                retry_after = response.headers.get("Retry-After", "")
                try:
                    delay = min(4.0, max(0.1, float(retry_after)))
                except ValueError:
                    delay = 0.5 * (2 ** attempt)
                await asyncio.sleep(delay)
        raise RuntimeError("OSV query retry loop exited unexpectedly")  # pragma: no cover


def _queryable_packages(
    inventory: dict[str, Any],
    max_packages: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    locked = list(inventory.get("locked_dependencies", []) or [])
    direct = list(inventory.get("dependencies", []) or [])
    candidates = locked + [
        item for item in direct if item.get("resolved_version") or item.get("pinned")
    ]
    packages = []
    gaps = list(inventory.get("coverage", {}).get("gaps", []) or [])
    seen = set()
    for item in candidates:
        ecosystem = str(item.get("ecosystem", ""))
        if ecosystem not in _OSV_ECOSYSTEMS:
            continue
        version = _exact_version(item.get("resolved_version") or item.get("version_spec"), ecosystem)
        if not version:
            continue
        key = (ecosystem, str(item.get("name", "")).lower(), version)
        if not item.get("name") or key in seen:
            continue
        seen.add(key)
        packages.append({
            "ecosystem": ecosystem,
            "name": str(item["name"]),
            "version": version,
            "provenance": dict(item.get("provenance", {}) or {}),
        })
        if len(packages) >= max_packages:
            break
    queryable_keys = {(item["ecosystem"], item["name"].lower()) for item in packages}
    skipped = [
        item for item in direct
        if (str(item.get("ecosystem", "")), str(item.get("name", "")).lower()) not in queryable_keys
    ]
    if skipped:
        gaps.append(
            f"Skipped {len(skipped)} direct dependencies without an exact resolved version"
        )
    if len(candidates) > max_packages:
        gaps.append(f"Dependency vulnerability query truncated at {max_packages} packages")
    return packages, list(dict.fromkeys(gaps))


def _exact_version(value: Any, ecosystem: str) -> str:
    text = str(value or "").strip()
    if ecosystem == "python":
        match = re.fullmatch(r"===?\s*([^,;\s]+)", text)
        return match.group(1) if match else text if re.fullmatch(r"\d+(?:\.\d+)+(?:[-+][\w.-]+)?", text) else ""
    if ecosystem in {"node", "cargo", "maven", "gradle"}:
        return text if re.fullmatch(r"v?\d+(?:\.\d+)+(?:[-+][\w.-]+)?", text) else ""
    if ecosystem == "go":
        return text if re.fullmatch(r"v\d+(?:\.\d+)+(?:[-+][\w.-]+)?", text) else ""
    return ""


def _normalize_vulnerability(package: dict[str, Any], value: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(value.get("id") or "OSV-UNKNOWN"),
        "aliases": [str(item) for item in list(value.get("aliases", []) or [])],
        "summary": str(value.get("summary") or value.get("details") or "Dependency vulnerability")[:1000],
        "severity": _severity(value),
        "package": {
            "ecosystem": package["ecosystem"],
            "osv_ecosystem": _OSV_ECOSYSTEMS[package["ecosystem"]],
            "name": package["name"],
            "version": package["version"],
        },
        "fixed_versions": _fixed_versions(value),
        "published": value.get("published"),
        "modified": value.get("modified"),
        "references": [
            str(item.get("url")) for item in list(value.get("references", []) or [])
            if isinstance(item, dict) and item.get("url")
        ][:20],
        "provenance": package["provenance"],
    }


def _severity(value: dict[str, Any]) -> str:
    database = value.get("database_specific") if isinstance(value.get("database_specific"), dict) else {}
    label = str(database.get("severity", "")).lower()
    if label in {"critical", "high", "medium", "low"}:
        return label
    for item in list(value.get("severity", []) or []):
        if not isinstance(item, dict):
            continue
        score = str(item.get("score", ""))
        match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*", score)
        if match is None:
            match = re.search(r"\bSCORE\s*:\s*(\d+(?:\.\d+)?)\b", score, re.IGNORECASE)
        if match:
            numeric = float(match.group(1))
            return "critical" if numeric >= 9 else "high" if numeric >= 7 else "medium" if numeric >= 4 else "low"
    return "medium"


def _fixed_versions(value: dict[str, Any]) -> list[str]:
    fixed = []
    for affected in list(value.get("affected", []) or []):
        if not isinstance(affected, dict):
            continue
        for range_value in list(affected.get("ranges", []) or []):
            if not isinstance(range_value, dict):
                continue
            for event in list(range_value.get("events", []) or []):
                if isinstance(event, dict) and event.get("fixed"):
                    fixed.append(str(event["fixed"]))
    return sorted(set(fixed))


def _base_output(
    inventory: dict[str, Any],
    packages: list[dict[str, Any]],
    gaps: list[str],
    queried_at: str,
) -> dict[str, Any]:
    return {
        "scanner": "osv",
        "endpoint": OSV_QUERY_BATCH_URL,
        "database_freshness": "live_query_without_snapshot_version",
        "queried_at": queried_at,
        "queried_package_count": len(packages),
        "packages": packages,
        "inventory_coverage": inventory.get("coverage", {}),
        "coverage": {
            "gaps": list(dict.fromkeys(gaps)),
            "complete": not gaps,
        },
    }


def _bounded(value: Any, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(maximum, int(value)))
    except (TypeError, ValueError):
        return minimum
