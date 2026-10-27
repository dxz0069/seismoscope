"""Explicitly authorized lifecycle for a containerized service under test."""

from __future__ import annotations

import asyncio
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from ..sanitization import redact_sensitive_text
from ..tool_fabric.container import ContainerProfile, ContainerToolRunner


@dataclass(frozen=True)
class ServiceSpec:
    image: str
    command: list[str]
    container_port: int
    health_path: str = "/"
    host_port: int = 0
    startup_timeout_seconds: float = 30.0
    environment: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.command or any(not isinstance(item, str) or "\x00" in item for item in self.command):
            raise ValueError("Service command must be a non-empty argument vector")
        executable = Path(self.command[0]).name.lower()
        if executable in {"sh", "bash", "cmd", "cmd.exe", "powershell", "pwsh", "wsl"}:
            raise ValueError("Shell executables are not permitted for service startup")
        if not 1 <= int(self.container_port) <= 65535:
            raise ValueError("container_port must be between 1 and 65535")
        if self.host_port and not 1024 <= int(self.host_port) <= 65535:
            raise ValueError("host_port must be zero or an unprivileged TCP port")
        if not str(self.health_path).startswith("/") or "\x00" in str(self.health_path):
            raise ValueError("health_path must be an absolute URL path")


@dataclass
class ServiceHandle:
    status: str
    container_name: str = ""
    network_name: str = ""
    base_url: str = ""
    health_url: str = ""
    error: str | None = None
    logs: str = ""
    started_at: float = 0.0

    @property
    def ready(self) -> bool:
        return self.status == "ready"


class ContainerServiceRunner:
    DEFAULT_ALLOWED_IMAGES = {
        "vibe-sec-tools:latest",
        "python:3.12-slim",
        "node:22-slim",
    }

    def __init__(
        self,
        *,
        docker_binary: str = "docker",
        allowed_images: set[str] | None = None,
    ):
        self.docker_binary = docker_binary
        self.allowed_images = set(allowed_images or self.DEFAULT_ALLOWED_IMAGES)
        self.command_builder = ContainerToolRunner(docker_binary=docker_binary)

    async def start(self, spec: ServiceSpec, *, project_root: str) -> ServiceHandle:
        if spec.image not in self.allowed_images:
            return ServiceHandle("blocked", error=f"Service image is not allowlisted: {spec.image}")
        root = Path(project_root).resolve()
        if not root.is_dir():
            return ServiceHandle("blocked", error="project_root must be an existing directory")
        suffix = uuid4().hex[:12]
        network_name = f"vibe-sec-service-{suffix}"
        container_name = f"vibe-sec-sut-{suffix}"
        host_port = spec.host_port or self._free_loopback_port()
        handle = ServiceHandle(
            "starting",
            container_name=container_name,
            network_name=network_name,
            base_url=f"http://127.0.0.1:{host_port}",
            health_url=f"http://127.0.0.1:{host_port}{spec.health_path}",
            started_at=time.monotonic(),
        )
        network = await self._run([
            self.docker_binary, "network", "create", "--driver", "bridge", network_name,
        ], timeout=10)
        if network[0] != 0:
            handle.status = "failed"
            handle.error = network[2] or "Failed to create internal service network"
            return handle

        try:
            profile = ContainerProfile(
                image=spec.image,
                network=network_name,
                memory_limit="512m",
                cpu_limit="1.0",
                pids_limit=256,
                workspace_mode="ro",
            )
            command = self.command_builder.build_command(
                spec.command,
                project_root=str(root),
                profile=profile,
                env=spec.environment,
            )
            image_index = len(command) - len(spec.command) - 1
            command[image_index:image_index] = [
                "--detach",
                "--name", container_name,
                "--publish", f"127.0.0.1:{host_port}:{spec.container_port}",
            ]
            started = await self._run(command, timeout=30)
            if started[0] != 0:
                handle.status = "failed"
                handle.error = started[2] or started[1] or "Service container failed to start"
                return handle
            ready = await self._wait_for_health(handle.health_url, spec.startup_timeout_seconds)
            if not ready:
                handle.status = "failed"
                handle.logs = await self.logs(handle)
                handle.error = f"Service health predicate did not pass: {handle.health_url}"
                return handle
            handle.status = "ready"
            return handle
        except (OSError, ValueError) as exc:
            handle.status = "failed"
            handle.error = str(exc)
            return handle
        finally:
            if handle.status != "ready":
                await self.stop(handle)

    async def stop(self, handle: ServiceHandle) -> None:
        if handle.container_name:
            await self._run([self.docker_binary, "rm", "-f", handle.container_name], timeout=15)
        if handle.network_name:
            await self._run([self.docker_binary, "network", "rm", handle.network_name], timeout=15)
        if handle.status == "ready":
            handle.status = "stopped"

    async def logs(self, handle: ServiceHandle) -> str:
        if not handle.container_name:
            return ""
        _, stdout, stderr = await self._run(
            [self.docker_binary, "logs", "--tail", "200", handle.container_name],
            timeout=10,
        )
        return redact_sensitive_text((stdout + "\n" + stderr)[-16_000:])

    async def _wait_for_health(self, url: str, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + max(1.0, float(timeout_seconds))
        while time.monotonic() < deadline:
            try:
                status = await asyncio.to_thread(self._probe, url)
                if 200 <= status < 500:
                    return True
            except (OSError, urllib.error.URLError):
                pass
            await asyncio.sleep(0.2)
        return False

    @staticmethod
    def _probe(url: str) -> int:
        request = urllib.request.Request(url, method="GET", headers={"User-Agent": "vibe-sec-health/1"})
        with urllib.request.urlopen(request, timeout=1) as response:
            return int(response.status)

    @staticmethod
    def _free_loopback_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    @staticmethod
    async def _run(command: list[str], *, timeout: float) -> tuple[int, str, str]:
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            return (
                int(process.returncode or 0),
                stdout.decode("utf-8", errors="replace")[-16_000:],
                stderr.decode("utf-8", errors="replace")[-16_000:],
            )
        except (TimeoutError, OSError) as exc:
            return -1, "", str(exc)
