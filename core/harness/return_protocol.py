"""Stable payload returned to a coding agent or Skill host."""

from collections.abc import Iterable
from typing import Any


def build_return_packages(
    findings: Iterable[dict[str, Any]],
    remediation_bundles: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    bundles = {bundle.get("finding_id"): bundle for bundle in remediation_bundles}
    returned: list[dict[str, Any]] = []
    for finding in findings:
        finding_id = finding.get("id", "")
        bundle = bundles.get(finding_id, {})
        returned.append(
            {
                "finding": {
                    key: finding.get(key)
                    for key in (
                        "id", "title", "severity", "vulnerability_type", "file_path", "line_start", "line_end",
                        "status", "verification_status", "lane",
                    )
                },
                "evidence": finding.get("evidence_bundle", {
                    "items": finding.get("evidence", []),
                    "gaps": finding.get("evidence_gaps", []),
                    "level": finding.get("evidence_level", 1),
                }),
                "risk_chain": finding.get("risk_chain"),
                "remediation": bundle,
                "return_contract": {
                    "package_id": bundle.get("package_id", f"REMEDIATION-{finding_id or 'unknown'}"),
                    "requires_human_confirmation": bool(
                        dict(bundle.get("approval_gate") or {}).get(
                            "required", finding.get("severity") in {"critical", "high"},
                        )
                    ),
                    "approval_gate": dict(bundle.get("approval_gate") or {}),
                    "retest_required": True,
                },
            }
        )
    return returned
