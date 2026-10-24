"""Local image capability checks used before scanner tools are exposed."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, Iterable, Set


@dataclass(frozen=True)
class ImageRequirement:
    image: str
    capabilities: Set[str]
    version: str = ""
    tool_versions: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ImagePreflightResult:
    image: str
    available: bool
    capabilities: Set[str] = field(default_factory=set)
    version: str = ""
    image_id: str = ""
    reason: str = ""
    tool_versions: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "image": self.image,
            "available": self.available,
            "capabilities": sorted(self.capabilities),
            "version": self.version,
            "image_id": self.image_id,
            "reason": self.reason,
            "tool_versions": dict(self.tool_versions),
        }


class ContainerImagePreflight:
    """Validate immutable scanner-image declarations without starting a container."""

    CAPABILITIES_LABEL = "io.vibe-sec.capabilities"
    VERSION_LABEL = "org.opencontainers.image.version"

    def __init__(self, *, docker_binary: str = "docker", timeout_seconds: float = 10):
        self.docker_binary = docker_binary
        self.timeout_seconds = max(1.0, float(timeout_seconds))

    def inspect(self, requirement: ImageRequirement) -> ImagePreflightResult:
        if shutil.which(self.docker_binary) is None:
            return ImagePreflightResult(
                requirement.image, False, reason=f"Container runtime not found: {self.docker_binary}",
            )
        try:
            completed = subprocess.run(
                [self.docker_binary, "image", "inspect", requirement.image],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ImagePreflightResult(requirement.image, False, reason=str(exc))
        if completed.returncode != 0:
            reason = completed.stderr.strip() or f"Image is not available: {requirement.image}"
            return ImagePreflightResult(requirement.image, False, reason=reason)
        try:
            payload = json.loads(completed.stdout)
            details = payload[0]
            labels = dict((details.get("Config") or {}).get("Labels") or {})
        except (json.JSONDecodeError, IndexError, TypeError, AttributeError) as exc:
            return ImagePreflightResult(
                requirement.image, False, reason=f"Invalid image inspection response: {exc}",
            )
        capabilities = _capability_set(labels.get(self.CAPABILITIES_LABEL, ""))
        version = str(labels.get(self.VERSION_LABEL, "") or "")
        tool_versions = {
            key.removeprefix("io.vibe-sec.tools.").removesuffix(".version"): str(value)
            for key, value in labels.items()
            if key.startswith("io.vibe-sec.tools.") and key.endswith(".version")
        }
        missing = requirement.capabilities - capabilities
        if missing:
            return ImagePreflightResult(
                requirement.image,
                False,
                capabilities,
                version,
                str(details.get("Id", "")),
                "Image is missing required capabilities: " + ", ".join(sorted(missing)),
                tool_versions,
            )
        if requirement.version and version != requirement.version:
            return ImagePreflightResult(
                requirement.image,
                False,
                capabilities,
                version,
                str(details.get("Id", "")),
                f"Image version {version or 'unknown'} does not match required {requirement.version}",
                tool_versions,
            )
        mismatched_tools = {
            name: (tool_versions.get(name, ""), expected)
            for name, expected in requirement.tool_versions.items()
            if tool_versions.get(name) != expected
        }
        if mismatched_tools:
            details_text = ", ".join(
                f"{name}={actual or 'unknown'} (required {expected})"
                for name, (actual, expected) in sorted(mismatched_tools.items())
            )
            return ImagePreflightResult(
                requirement.image,
                False,
                capabilities,
                version,
                str(details.get("Id", "")),
                "Image tool versions do not match: " + details_text,
                tool_versions,
            )
        return ImagePreflightResult(
            requirement.image,
            True,
            capabilities,
            version,
            str(details.get("Id", "")),
            "Image capability and version labels accepted",
            tool_versions,
        )


def _capability_set(value: str | Iterable[str]) -> Set[str]:
    if isinstance(value, str):
        values = value.split(",")
    else:
        values = value
    return {str(item).strip() for item in values if str(item).strip()}
