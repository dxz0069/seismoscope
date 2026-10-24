"""Hardened container runner for fixed security-tool adapter commands."""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass(frozen=True)
class ContainerProfile:
    image: str = "vibe-sec-tools:latest"
    network: str = "none"
    memory_limit: str = "512m"
    cpu_limit: str = "1.0"
    pids_limit: int = 256
    user: str = "65532:65532"
    workspace_mount: str = "/workspace"
    workspace_mode: str = "ro"
    read_only_root: bool = True
    tmpfs: List[str] = field(default_factory=lambda: ["/tmp:rw,noexec,nosuid,size=128m"])

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9._/:@-]+", self.image):
            raise ValueError("Container image contains unsupported characters")
        service_network = re.fullmatch(r"vibe-sec-service-[a-f0-9]{12}", self.network)
        if self.network not in {"none", "bridge"} and not service_network:
            raise ValueError("Container network must be none, bridge, or a managed Vibe Sec service network")
        if self.workspace_mode not in {"ro", "rw"}:
            raise ValueError("workspace_mode must be ro or rw")


@dataclass
class ContainerRunResult:
    status: str
    command: List[str]
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    error: Optional[str] = None
    output_truncated: bool = False

    @property
    def success(self) -> bool:
        return self.status == "completed" and self.exit_code == 0


class ContainerToolRunner:
    def __init__(self, *, docker_binary: str = "docker", max_output_bytes: int = 4_000_000):
        self.docker_binary = docker_binary
        self.max_output_bytes = max(16_384, int(max_output_bytes))

    @property
    def available(self) -> bool:
        return shutil.which(self.docker_binary) is not None

    def build_command(
        self,
        command: List[str],
        *,
        project_root: str,
        profile: ContainerProfile,
        env: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        if not command or any(not isinstance(item, str) or "\x00" in item for item in command):
            raise ValueError("Container command must be a non-empty string argument list")
        project = Path(project_root).resolve()
        if not project.is_dir():
            raise ValueError("project_root must be an existing directory")
        docker_command = [
            self.docker_binary,
            "run",
            "--rm",
            "--network",
            profile.network,
            "--memory",
            profile.memory_limit,
            "--cpus",
            profile.cpu_limit,
            "--pids-limit",
            str(profile.pids_limit),
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--user",
            profile.user,
            "--workdir",
            profile.workspace_mount,
            "--mount",
            f"type=bind,source={project},target={profile.workspace_mount},{profile.workspace_mode}",
        ]
        if profile.read_only_root:
            docker_command.append("--read-only")
        for item in profile.tmpfs:
            docker_command.extend(["--tmpfs", item])
        for key, value in sorted((env or {}).items()):
            if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
                raise ValueError(f"Invalid environment variable name: {key}")
            docker_command.extend(["--env", f"{key}={value}"])
        return [*docker_command, profile.image, *command]

    async def run(
        self,
        command: List[str],
        *,
        project_root: str,
        profile: ContainerProfile,
        timeout_seconds: float = 120,
        env: Optional[Dict[str, str]] = None,
    ) -> ContainerRunResult:
        full_command = self.build_command(
            command,
            project_root=project_root,
            profile=profile,
            env=env,
        )
        if not self.available:
            return ContainerRunResult(
                status="unavailable",
                command=full_command,
                error=f"Container runtime not found: {self.docker_binary}",
            )
        started = time.monotonic()
        try:
            process = await asyncio.create_subprocess_exec(
                *full_command,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=os.environ.copy(),
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=max(1.0, float(timeout_seconds)),
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return ContainerRunResult(
                    status="timed_out",
                    command=full_command,
                    duration_ms=int((time.monotonic() - started) * 1_000),
                    error=f"Container tool timed out after {timeout_seconds:g}s",
                )
            stdout, stdout_truncated = self._bounded_decode(stdout)
            stderr, stderr_truncated = self._bounded_decode(stderr)
            exit_code = int(process.returncode or 0)
            return ContainerRunResult(
                status="completed" if exit_code == 0 else "failed",
                command=full_command,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_ms=int((time.monotonic() - started) * 1_000),
                error=None if exit_code == 0 else f"Container tool exited with code {exit_code}",
                output_truncated=stdout_truncated or stderr_truncated,
            )
        except OSError as exc:
            return ContainerRunResult(
                status="unavailable",
                command=full_command,
                duration_ms=int((time.monotonic() - started) * 1_000),
                error=str(exc),
            )

    def _bounded_decode(self, content: bytes) -> tuple[str, bool]:
        truncated = len(content) > self.max_output_bytes
        return content[:self.max_output_bytes].decode("utf-8", errors="replace"), truncated
