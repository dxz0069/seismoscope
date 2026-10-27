"""Run deterministic container scanners and normalize their candidate signals."""

from __future__ import annotations

import asyncio
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..runtime.permission_policy import PermissionPolicy
from ..tool_fabric import (
    ArtifactStore,
    ContainerProfile,
    OsvVulnerabilityAdapter,
    ToolGateway,
    ToolRegistry,
    ToolRequest,
    register_container_scanners,
)


@dataclass
class ScannerCollectionResult:
    signals: list[dict[str, Any]] = field(default_factory=list)
    executions: list[dict[str, Any]] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_count": len(self.signals),
            "signals": self.signals,
            "executions": self.executions,
            "artifact_refs": self.artifact_refs,
            "gaps": self.gaps,
        }


class ContainerScannerCollector:
    def __init__(
        self,
        project_path: str,
        *,
        image: str = "vibe-sec-tools:latest",
        runner=None,
        artifact_root: str | None = None,
    ):
        self.project_root = Path(project_path).resolve()
        registry = ToolRegistry()
        register_container_scanners(
            registry,
            runner=runner,
            profile=ContainerProfile(image=image),
        )
        root = artifact_root or str(Path(tempfile.gettempdir()) / "vibe-sec-artifacts")
        self.gateway = ToolGateway(
            registry,
            project_root=str(self.project_root),
            artifact_store=ArtifactStore(root, session_id=f"scanners-{self.project_root.name}"),
            policy=PermissionPolicy(allow_network_access=False, allow_file_write=False),
        )

    async def collect(self, lane: str) -> ScannerCollectionResult:
        requests = []
        if lane in {"web_audit", "agent_audit", "mcp_audit", "workflow_audit"}:
            rule_pack = {
                "agent_audit": "agent",
                "mcp_audit": "agent",
                "workflow_audit": "web",
            }.get(lane, "web")
            requests.append(ToolRequest(
                tool_name="semgrep_scan",
                arguments={"path": ".", "rule_pack": rule_pack, "max_results": 500},
                session_id="scanner",
                task_id=lane,
            ))
        if lane == "web_audit":
            requests.extend([
                ToolRequest(
                    tool_name="bandit_scan",
                    arguments={"path": ".", "max_results": 500},
                    session_id="scanner",
                    task_id=lane,
                ),
                ToolRequest(
                    tool_name="trivy_filesystem_scan",
                    arguments={
                        "path": ".", "scanners": "vuln,misconfig,secret", "max_results": 1000,
                    },
                    session_id="scanner",
                    task_id=lane,
                ),
            ])
        if lane == "secrets_audit":
            requests.append(ToolRequest(
                tool_name="gitleaks_scan",
                arguments={"path": ".", "max_results": 500},
                session_id="scanner",
                task_id=lane,
            ))
        executions = await asyncio.gather(*(self.gateway.execute(request) for request in requests))
        result = ScannerCollectionResult()
        for execution in executions:
            result.executions.append(execution.to_dict())
            result.signals.extend(signal.to_dict() for signal in execution.signals)
            result.artifact_refs.extend(artifact.artifact_id for artifact in execution.artifacts)
            if execution.status.value != "completed":
                result.gaps.append(
                    f"{execution.tool_name} unavailable or failed: {execution.error or execution.policy_reason}"
                )
        result.artifact_refs = list(dict.fromkeys(result.artifact_refs))
        return result


class DependencyVulnerabilityCollector:
    """Run the fixed-endpoint OSV adapter only after trusted network authorization."""

    def __init__(
        self,
        project_path: str,
        *,
        artifact_root: str | None = None,
        adapter: OsvVulnerabilityAdapter | None = None,
    ):
        self.project_root = Path(project_path).resolve()
        registry = ToolRegistry()
        registry.register(adapter or OsvVulnerabilityAdapter())
        root = artifact_root or str(Path(tempfile.gettempdir()) / "vibe-sec-artifacts")
        self.gateway = ToolGateway(
            registry,
            project_root=str(self.project_root),
            artifact_store=ArtifactStore(root, session_id=f"dependency-{self.project_root.name}"),
            policy=PermissionPolicy(
                allowed_domains=["api.osv.dev"],
                allow_network_access=True,
                allow_file_write=False,
            ),
        )

    async def collect(self) -> ScannerCollectionResult:
        execution = await self.gateway.execute(ToolRequest(
            tool_name="query_dependency_vulnerabilities",
            arguments={"max_packages": 1000, "max_vulnerabilities": 2000},
            session_id="scanner",
            task_id="dependency_audit",
        ))
        result = ScannerCollectionResult(
            signals=[signal.to_dict() for signal in execution.signals],
            executions=[execution.to_dict()],
            artifact_refs=[artifact.artifact_id for artifact in execution.artifacts],
        )
        if execution.status.value != "completed":
            result.gaps.append(
                f"OSV dependency scanner unavailable or failed: {execution.error or execution.policy_reason}"
            )
        elif execution.output.get("coverage", {}).get("gaps"):
            result.gaps.extend(str(item) for item in execution.output["coverage"]["gaps"])
        return result
