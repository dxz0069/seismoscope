"""Compatibility wrapper for controlled, predicate-bound container execution.

The verification Agent still imports ``DockerExecutor``.  Internally all runs
use the hardened Tool Fabric container runner: no shell interpolation, no
network, a read-only root, dropped capabilities, and bounded resources.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.sanitization import redact_sensitive_text
from core.tool_fabric.container import ContainerProfile, ContainerRunResult, ContainerToolRunner


@dataclass
class ExecutionResult:
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float
    error: str | None = None
    status: str = "completed"
    output_truncated: bool = False


class DockerExecutor:
    """Execute an approved argument vector in a resource-bounded container."""

    _daemon_cache: dict[str, tuple[float, bool]] = {}

    def __init__(
        self,
        image: str = "python:3.12-slim",
        network_disabled: bool = True,
        memory_limit: str = "256m",
        cpu_limit: str = "0.5",
        *,
        docker_binary: str = "docker",
        pids_limit: int = 128,
        max_output_bytes: int = 1_000_000,
    ):
        self.image = image
        self.network_disabled = network_disabled
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.docker_binary = docker_binary
        self.pids_limit = pids_limit
        self.runner = ContainerToolRunner(
            docker_binary=docker_binary,
            max_output_bytes=max_output_bytes,
        )
        self._docker_available = self._check_docker()

    def _check_docker(self) -> bool:
        """Check both the Docker client and daemon, with a short-lived cache."""
        if shutil.which(self.docker_binary) is None:
            return False
        cached = self._daemon_cache.get(self.docker_binary)
        now = time.monotonic()
        if cached and now - cached[0] < 30:
            return cached[1]
        try:
            completed = subprocess.run(
                [self.docker_binary, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            available = completed.returncode == 0 and bool(completed.stdout.strip())
        except (OSError, subprocess.TimeoutExpired):
            available = False
        self._daemon_cache[self.docker_binary] = (now, available)
        return available

    async def execute_python(
        self,
        code: str,
        timeout: int = 30,
        env_vars: dict[str, str] | None = None,
    ) -> ExecutionResult:
        return await self._execute_in_docker(
            ["python", "-I", "-c", str(code)],
            timeout=timeout,
            env_vars=env_vars,
        )

    async def execute_javascript(
        self,
        code: str,
        timeout: int = 30,
        env_vars: dict[str, str] | None = None,
    ) -> ExecutionResult:
        return await self._execute_in_docker(
            ["node", "--disable-proto=delete", "-e", str(code)],
            timeout=timeout,
            env_vars=env_vars,
        )

    async def execute_command(
        self,
        command: list[str],
        timeout: int = 30,
        env_vars: dict[str, str] | None = None,
        *,
        project_path: str | None = None,
    ) -> ExecutionResult:
        return await self._execute_in_docker(
            command,
            timeout=timeout,
            env_vars=env_vars,
            project_path=project_path,
        )

    async def _execute_in_docker(
        self,
        command: list[str],
        volumes: dict[str, Any] | None = None,
        timeout: int = 30,
        env_vars: dict[str, str] | None = None,
        project_path: str | None = None,
    ) -> ExecutionResult:
        if volumes:
            return ExecutionResult(
                False, "", "", -1, 0.0,
                "Ad hoc volume mappings are not permitted; use project_path",
                status="blocked",
            )
        if not self._docker_available:
            return ExecutionResult(
                False, "", "", -1, 0.0,
                "Docker daemon is not available",
                status="unavailable",
            )

        temporary = None
        if project_path is None:
            temporary = tempfile.TemporaryDirectory(prefix="vibe-sec-verify-")
            project_path = temporary.name
        try:
            profile = ContainerProfile(
                image=self.image,
                network="none" if self.network_disabled else "bridge",
                memory_limit=self.memory_limit,
                cpu_limit=self.cpu_limit,
                pids_limit=self.pids_limit,
                workspace_mode="ro",
            )
            run = await self.runner.run(
                list(command),
                project_root=str(Path(project_path).resolve()),
                profile=profile,
                timeout_seconds=max(1, timeout),
                env=dict(env_vars or {}),
            )
            return self._convert(run)
        finally:
            if temporary:
                temporary.cleanup()

    async def verify_vulnerability(
        self,
        vuln_type: str,
        code: str,
        exploit_code: str | None = None,
        *,
        oracle_id: str = "",
        target_path: str = "target.py",
        project_path: str | None = None,
    ) -> dict[str, Any]:
        """Run an explicit harness; execution alone can never verify a finding."""
        if not exploit_code or not str(exploit_code).strip():
            return {
                "verified": False,
                "status": "needs_evidence",
                "verification_predicate": "",
                "explanation": "An explicit exploit harness and predicate are required",
                "evidence": "No exploit_code was supplied; target code was not executed",
            }
        if oracle_id != "python.command-sink-differential.v1":
            return {
                "verified": False,
                "status": "needs_evidence",
                "verification_predicate": "Harness-owned oracle profile is registered",
                "explanation": "No supported Harness-owned oracle was selected",
                "evidence": "",
            }
        script = self._build_verification_script(
            vuln_type, code, exploit_code, oracle_id=oracle_id, target_path=target_path,
        )
        result = await self._execute_in_docker(
            ["python", "-I", "-c", script], timeout=60, project_path=project_path,
        )
        if not result.success:
            return {
                "verified": False,
                "status": "needs_evidence",
                "verification_predicate": "VIBE_SEC_VERIFIED is exactly true",
                "explanation": result.error or result.stderr or "Harness execution failed",
                "evidence": result.stdout,
                "execution_status": result.status,
            }
        try:
            payload = json.loads(next(
                line for line in reversed(result.stdout.splitlines()) if line.strip()
            ))
        except (json.JSONDecodeError, StopIteration):
            return {
                "verified": False,
                "status": "needs_evidence",
                "verification_predicate": "VIBE_SEC_VERIFIED is exactly true",
                "explanation": "Harness did not emit the required JSON terminal result",
                "evidence": result.stdout,
            }
        payload["verified"] = payload.get("verified") is True
        payload["status"] = "verified" if payload["verified"] else "needs_evidence"
        return payload

    @staticmethod
    def _build_verification_script(
        vuln_type: str,
        code: str,
        exploit_code: str,
        *,
        oracle_id: str = "python.command-sink-differential.v1",
        target_path: str = "target.py",
    ) -> str:
        return f'''import inspect
import json
import os
import subprocess

oracle_id = {oracle_id!r}
target_filename = "/workspace/" + {target_path!r}.replace("\\\\", "/").lstrip("/")
target_code_objects = set()
events = []

def _from_bound_target():
    return any(frame.frame.f_code in target_code_objects for frame in inspect.stack()[2:])

def _record(sink, args):
    if _from_bound_target():
        events.append({{"sink": sink, "arguments": repr(args)[:500]}})

def _os_system(*args, **kwargs):
    _record("os.system", args)
    return 0

def _subprocess_run(*args, **kwargs):
    _record("subprocess.run", args)
    return subprocess.CompletedProcess(args[0] if args else [], 0, "", "")

class _PopenResult:
    returncode = 0
    def communicate(self, *args, **kwargs):
        return (b"", b"")
    def wait(self, *args, **kwargs):
        return 0

def _subprocess_popen(*args, **kwargs):
    _record("subprocess.Popen", args)
    return _PopenResult()

def _subprocess_bytes(*args, **kwargs):
    _record("subprocess.check_output", args)
    return b""

def _subprocess_zero(*args, **kwargs):
    _record("subprocess.call", args)
    return 0

os.system = _os_system
subprocess.run = _subprocess_run
subprocess.Popen = _subprocess_popen
subprocess.call = _subprocess_zero
subprocess.check_call = _subprocess_zero
subprocess.check_output = _subprocess_bytes

namespace = {{"__name__": "__vibe_sec_target__", "__file__": target_filename}}
try:
    compiled_target = compile({code!r}, target_filename, "exec")
    target_code_objects.add(compiled_target)
    exec(compiled_target, namespace, namespace)
    for value in list(namespace.values()):
        code_object = getattr(value, "__code__", None)
        if code_object is not None:
            target_code_objects.add(code_object)
        if isinstance(value, type):
            for member in vars(value).values():
                member_code = getattr(member, "__code__", None)
                if member_code is not None:
                    target_code_objects.add(member_code)
    exec(compile({exploit_code!r}, "<vibe-sec-control>", "exec"), namespace, namespace)
    verified = bool(events)
    result = {{
        "vulnerability_type": {vuln_type!r},
        "verified": verified,
        "oracle_id": oracle_id,
        "verification_predicate": "A command sink call originates from bound target code",
        "explanation": "Bound target reached a command sink" if verified else "No bound target command sink event was observed",
        "events": events,
    }}
except Exception as exc:
    result = {{
        "vulnerability_type": {vuln_type!r},
        "verified": False,
        "oracle_id": oracle_id,
        "verification_predicate": "A command sink call originates from bound target code",
        "explanation": "Harness raised an exception: " + str(exc),
        "events": events,
    }}
print(json.dumps(result))
'''

    @staticmethod
    def _convert(run: ContainerRunResult) -> ExecutionResult:
        return ExecutionResult(
            success=run.success,
            stdout=redact_sensitive_text(run.stdout),
            stderr=redact_sensitive_text(run.stderr),
            exit_code=run.exit_code,
            execution_time=run.duration_ms / 1_000,
            error=redact_sensitive_text(run.error) if run.error else None,
            status=run.status,
            output_truncated=run.output_truncated,
        )
