"""Unified security-tool contracts and controlled execution gateway."""

from .artifacts import ArtifactStore
from .container import ContainerProfile, ContainerRunResult, ContainerToolRunner
from .dependency_vulnerabilities import OsvVulnerabilityAdapter
from .gateway import ToolExecutionContext, ToolGateway
from .image_preflight import ContainerImagePreflight, ImagePreflightResult, ImageRequirement
from .models import (
    ArtifactRef,
    ToolAdapterError,
    ToolExecution,
    ToolExecutionStatus,
    ToolRequest,
    ToolResult,
    ToolRiskClass,
    ToolSignal,
    ToolSpec,
)
from .registry import CallableToolAdapter, ToolAdapter, ToolRegistry
from .source_tools import SourceToolSuite, build_source_registry, source_tool_specs
from .scanner_adapters import (
    BanditAdapter,
    CodeQLAdapter,
    GitleaksAdapter,
    NucleiAdapter,
    SemgrepAdapter,
    TrivyAdapter,
    register_active_scanners,
    register_container_scanners,
)

__all__ = [
    "ArtifactRef",
    "ArtifactStore",
    "CallableToolAdapter",
    "ContainerProfile",
    "ContainerRunResult",
    "ContainerToolRunner",
    "ContainerImagePreflight",
    "GitleaksAdapter",
    "BanditAdapter",
    "CodeQLAdapter",
    "NucleiAdapter",
    "ImagePreflightResult",
    "ImageRequirement",
    "TrivyAdapter",
    "OsvVulnerabilityAdapter",
    "ToolAdapter",
    "ToolAdapterError",
    "ToolExecution",
    "ToolExecutionContext",
    "ToolExecutionStatus",
    "ToolGateway",
    "ToolRegistry",
    "ToolRequest",
    "ToolResult",
    "ToolRiskClass",
    "ToolSignal",
    "ToolSpec",
    "SourceToolSuite",
    "SemgrepAdapter",
    "build_source_registry",
    "source_tool_specs",
    "register_container_scanners",
    "register_active_scanners",
]
