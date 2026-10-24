"""Logical audit lanes used by the deterministic merge stage."""

from collections import defaultdict
from enum import Enum
from typing import Any, Dict, Iterable, List


class AuditLane(str, Enum):
    WEB = "web_audit"
    AGENT = "agent_audit"
    MCP = "mcp_audit"
    SECRETS = "secrets_audit"
    WORKFLOW = "workflow_audit"


def classify_lane(finding: Dict[str, Any]) -> str:
    value = str(finding.get("vulnerability_type", "")).lower()
    if value in {"prompt_injection", "excessive_agency", "unsafe_output_handling", "agent_insecurity"}:
        return AuditLane.AGENT.value
    if value.startswith("mcp") or value in {"tool_poisoning", "resource_exposure"}:
        return AuditLane.MCP.value
    if value in {"hardcoded_password", "api_key", "secret_leak", "credential_exposure"}:
        return AuditLane.SECRETS.value
    if value in {"ssrf", "arbitrary_code_execution", "code_injection", "workflow_insecurity", "idor", "file_access"}:
        return AuditLane.WORKFLOW.value
    return AuditLane.WEB.value


def group_findings_by_lane(findings: Iterable[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        lane = finding.get("lane") or classify_lane(finding)
        finding["lane"] = lane
        grouped[lane].append(finding)
    return dict(grouped)
