"""Controlled multi-service reproduction environments for verification."""

from __future__ import annotations

import asyncio
import json
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..sanitization import redact_sensitive_text
from ..tool_fabric.container import ContainerProfile, ContainerRunResult, ContainerToolRunner

_SHELLS = {"sh", "bash", "cmd", "cmd.exe", "powershell", "pwsh", "wsl"}


@dataclass(frozen=True)
class EnvironmentServiceSpec:
    name: str
    image: str
    command: list[str]
    container_port: int = 0
    health_path: str = "/"
    health_command: list[str] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    publish: bool = False

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", self.name):
            raise ValueError("Service name must match [a-z][a-z0-9-]{0,31}")
        if not self.command or any(not isinstance(item, str) or "\x00" in item for item in self.command):
            raise ValueError(f"Service {self.name} command must be a non-empty argument vector")
        if Path(self.command[0]).name.lower() in _SHELLS:
            raise ValueError(f"Shell executables are not permitted for service {self.name}")
        if self.health_command and Path(self.health_command[0]).name.lower() in _SHELLS:
            raise ValueError(f"Shell health checks are not permitted for service {self.name}")
        if self.container_port and not 1 <= int(self.container_port) <= 65535:
            raise ValueError(f"Service {self.name} container_port must be between 1 and 65535")
        if self.publish and not self.container_port:
            raise ValueError(f"Published service {self.name} requires container_port")
        if not self.health_path.startswith("/") or "\x00" in self.health_path:
            raise ValueError(f"Service {self.name} health_path must be an absolute path")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> EnvironmentServiceSpec:
        return cls(
            name=str(value.get("name", "")),
            image=str(value.get("image", "")),
            command=[str(item) for item in value.get("command", []) or []],
            container_port=int(value.get("container_port", 0) or 0),
            health_path=str(value.get("health_path", "/") or "/"),
            health_command=[str(item) for item in value.get("health_command", []) or []],
            environment={str(key): str(item) for key, item in dict(value.get("environment") or {}).items()},
            depends_on=[str(item) for item in value.get("depends_on", []) or []],
            publish=bool(value.get("publish", False)),
        )


@dataclass(frozen=True)
class ReproductionEnvironmentPlan:
    services: list[EnvironmentServiceSpec]
    target_service: str
    startup_timeout_seconds: float = 45.0
    internal_network: bool = True

    def __post_init__(self) -> None:
        if not 1 <= len(self.services) <= 8:
            raise ValueError("Environment must contain between 1 and 8 services")
        names = [item.name for item in self.services]
        if len(names) != len(set(names)):
            raise ValueError("Environment service names must be unique")
        if self.target_service not in names:
            raise ValueError("target_service must identify a declared service")
        published = [item.name for item in self.services if item.publish]
        if published:
            raise ValueError("Internal reproduction services cannot publish host ports")
        for service in self.services:
            unknown = sorted(set(service.depends_on) - set(names))
            if unknown:
                raise ValueError(f"Service {service.name} has unknown dependencies: {', '.join(unknown)}")
            if service.name in service.depends_on:
                raise ValueError(f"Service {service.name} cannot depend on itself")
        if not self.internal_network:
            raise ValueError("Outbound-capable reproduction networks are not supported")
        if not 1 <= float(self.startup_timeout_seconds) <= 300:
            raise ValueError("startup_timeout_seconds must be between 1 and 300")
        self.ordered_services()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ReproductionEnvironmentPlan:
        return cls(
            services=[EnvironmentServiceSpec.from_dict(item) for item in value.get("services", []) or []],
            target_service=str(value.get("target_service", "")),
            startup_timeout_seconds=float(value.get("startup_timeout_seconds", 45) or 45),
            internal_network=bool(value.get("internal_network", True)),
        )

    def ordered_services(self) -> list[EnvironmentServiceSpec]:
        by_name = {item.name: item for item in self.services}
        remaining = set(by_name)
        ordered: list[EnvironmentServiceSpec] = []
        while remaining:
            ready = sorted(
                name for name in remaining
                if set(by_name[name].depends_on).issubset({item.name for item in ordered})
            )
            if not ready:
                raise ValueError("Environment service dependencies contain a cycle")
            for name in ready:
                ordered.append(by_name[name])
                remaining.remove(name)
        return ordered


@dataclass
class ReproductionEnvironmentHandle:
    status: str
    network_name: str = ""
    containers: dict[str, str] = field(default_factory=dict)
    base_url: str = ""
    health_url: str = ""
    error: str | None = None
    service_logs: dict[str, str] = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        return self.status == "ready"


class ContainerEnvironmentRunner:
    DEFAULT_ALLOWED_IMAGES = {
        "python:3.12-slim",
        "node:22-slim",
        "postgres:16-alpine",
        "redis:7-alpine",
        "mysql:8.4",
        "vibe-sec-tools:latest",
    }

    def __init__(self, *, docker_binary: str = "docker", allowed_images: set[str] | None = None):
        self.docker_binary = docker_binary
        self.allowed_images = set(allowed_images or self.DEFAULT_ALLOWED_IMAGES)
        self.command_builder = ContainerToolRunner(docker_binary=docker_binary)

    async def start(
        self,
        plan: ReproductionEnvironmentPlan,
        *,
        project_root: str,
    ) -> ReproductionEnvironmentHandle:
        root = Path(project_root).resolve()
        if not root.is_dir():
            return ReproductionEnvironmentHandle("blocked", error="project_root must be an existing directory")
        denied = sorted({item.image for item in plan.services if item.image not in self.allowed_images})
        if denied:
            return ReproductionEnvironmentHandle(
                "blocked", error="Environment image is not allowlisted: " + ", ".join(denied),
            )
        suffix = uuid4().hex[:12]
        network_name = f"vibe-sec-service-{suffix}"
        handle = ReproductionEnvironmentHandle("starting", network_name=network_name)
        network = await self._run([
            self.docker_binary, "network", "create", "--driver", "bridge", "--internal", network_name,
        ], timeout=10)
        if network[0] != 0:
            handle.status = "failed"
            handle.error = network[2] or "Failed to create isolated environment network"
            return handle

        try:
            for service in plan.ordered_services():
                container_name = f"vibe-sec-env-{suffix}-{service.name}"
                profile = ContainerProfile(
                    image=service.image,
                    network=network_name,
                    memory_limit="512m",
                    cpu_limit="1.0",
                    pids_limit=256,
                    workspace_mode="ro",
                )
                command = self.command_builder.build_command(
                    service.command,
                    project_root=str(root),
                    profile=profile,
                    env=service.environment,
                )
                image_index = len(command) - len(service.command) - 1
                options = ["--detach", "--name", container_name, "--network-alias", service.name]
                if service.name == plan.target_service and service.container_port:
                    handle.base_url = f"http://{service.name}:{service.container_port}"
                    handle.health_url = handle.base_url + service.health_path
                command[image_index:image_index] = options
                started = await self._run(command, timeout=30)
                if started[0] != 0:
                    raise RuntimeError(started[2] or started[1] or f"Service {service.name} failed to start")
                handle.containers[service.name] = container_name
                ready = await self._wait_for_service(
                    service,
                    container_name,
                    "",
                    plan.startup_timeout_seconds,
                )
                if not ready:
                    raise RuntimeError(f"Service readiness predicate failed: {service.name}")
            handle.status = "ready"
            return handle
        except (OSError, RuntimeError, ValueError) as exc:
            handle.status = "failed"
            handle.error = str(exc)
            handle.service_logs = await self._collect_logs(handle)
            await self.stop(handle)
            return handle

    async def stop(self, handle: ReproductionEnvironmentHandle) -> None:
        for container_name in reversed(list(handle.containers.values())):
            await self._run([self.docker_binary, "rm", "-f", container_name], timeout=15)
        if handle.network_name:
            await self._run([self.docker_binary, "network", "rm", handle.network_name], timeout=15)
        if handle.status == "ready":
            handle.status = "stopped"

    async def logs(self, handle: ReproductionEnvironmentHandle) -> str:
        handle.service_logs = await self._collect_logs(handle)
        return json.dumps(handle.service_logs, ensure_ascii=False, sort_keys=True)

    async def run_control(
        self,
        handle: ReproductionEnvironmentHandle,
        command: list[str],
        *,
        project_root: str,
        image: str = "python:3.12-slim",
        timeout_seconds: float = 60,
    ) -> ContainerRunResult:
        if not handle.ready or not handle.network_name:
            return ContainerRunResult("unavailable", [], error="Reproduction environment is not ready")
        if image not in self.allowed_images:
            return ContainerRunResult("blocked", [], error=f"Verifier image is not allowlisted: {image}")
        profile = ContainerProfile(
            image=image,
            network=handle.network_name,
            memory_limit="256m",
            cpu_limit="0.5",
            pids_limit=128,
            workspace_mode="ro",
        )
        return await self.command_builder.run(
            command,
            project_root=project_root,
            profile=profile,
            timeout_seconds=timeout_seconds,
        )

    async def _collect_logs(self, handle: ReproductionEnvironmentHandle) -> dict[str, str]:
        logs: dict[str, str] = {}
        for service, container_name in handle.containers.items():
            _, stdout, stderr = await self._run(
                [self.docker_binary, "logs", "--tail", "200", container_name], timeout=10,
            )
            logs[service] = redact_sensitive_text((stdout + "\n" + stderr)[-16_000:])
        return logs

    async def _wait_for_service(
        self,
        spec: EnvironmentServiceSpec,
        container_name: str,
        health_url: str,
        timeout_seconds: float,
    ) -> bool:
        deadline = time.monotonic() + max(1.0, timeout_seconds)
        while time.monotonic() < deadline:
            if spec.health_command:
                check = await self._run(
                    [self.docker_binary, "exec", container_name, *spec.health_command], timeout=5,
                )
                if check[0] == 0:
                    return True
            elif health_url:
                try:
                    status = await asyncio.to_thread(self._probe, health_url)
                    if 200 <= status < 500:
                        return True
                except (OSError, urllib.error.URLError):
                    pass
            else:
                check = await self._run([
                    self.docker_binary, "inspect", "--format", "{{.State.Running}}", container_name,
                ], timeout=5)
                if check[0] == 0 and check[1].strip().lower() == "true":
                    return True
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
