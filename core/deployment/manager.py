"""Deterministic local setup, update, and diagnostics for the Skill runtime."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..languages.tree_sitter_gateway import status as tree_sitter_status
from ..languages.tree_sitter_gateway import warmup as tree_sitter_warmup
from ..tool_fabric.image_preflight import (
    ContainerImagePreflight,
    ImageRequirement,
)


class DeploymentManager:
    def __init__(
        self,
        *,
        root: str | None = None,
        manifest_path: str | None = None,
        docker_binary: str = "docker",
    ):
        self.root = Path(root).resolve() if root else Path(__file__).resolve().parents[2]
        self.manifest_path = Path(manifest_path).resolve() if manifest_path else (
            self.root / "manifests" / "tool-images.lock.json"
        )
        self.docker_binary = docker_binary
        self.manifest = self._load_manifest()
        self.images = {str(item["id"]): dict(item) for item in self.manifest["images"]}

    def doctor(self) -> dict[str, Any]:
        docker = self._docker_status()
        image_results = [self._inspect_image(item) for item in self.manifest["images"]]
        required_gaps = [
            item["id"] for item in image_results
            if item["default_install"] and not item["available"]
        ]
        optional_gaps = [
            item["id"] for item in image_results
            if not item["default_install"] and not item["available"]
        ]
        llm_variables = ["VIBE_SEC_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY"]
        platform_block = {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "python_supported": sys.version_info >= (3, 11),
        }
        ts = tree_sitter_status()
        capabilities = self._capabilities(
            docker=docker,
            required_gaps=required_gaps,
            optional_gaps=optional_gaps,
            python_supported=platform_block["python_supported"],
            ts=ts,
            llm_configured=any(os.getenv(name) for name in llm_variables),
        )
        # 三态判定：静态核心（纯 Python 泳道）是硬门槛；AST 与容器验证
        # 各有降级路径，缺失只降级不阻断。可选能力（LLM/CodeQL）不参与
        # 状态判定——未配置是默认形态而非故障。
        static_ok = capabilities["static_audit"]["available"]
        full_ok = all(
            info["available"] for info in capabilities.values() if not info["optional"]
        )
        if not static_ok:
            status = "not_ready"
        elif full_ok:
            status = "ready"
        else:
            status = "degraded_ready"
        return {
            "contract_version": "vibe-sec.doctor.v2",
            "status": status,
            "degraded_capabilities": [
                name for name, info in capabilities.items()
                if not info["optional"] and not info["available"]
            ],
            "capabilities": capabilities,
            "release": self.manifest.get("release"),
            "platform": platform_block,
            "docker": docker,
            "images": image_results,
            "llm": {
                "configured": any(os.getenv(name) for name in llm_variables),
                "accepted_environment_variables": llm_variables,
                "credential_values_exposed": False,
            },
            "tree_sitter": ts,
            "required_gaps": required_gaps,
            "optional_gaps": optional_gaps,
            "workspace": {
                "root": str(self.root),
                "free_bytes": shutil.disk_usage(self.root).free,
            },
        }

    @staticmethod
    def _capabilities(
        *,
        docker: dict[str, Any],
        required_gaps: list[str],
        optional_gaps: list[str],
        python_supported: bool,
        ts: dict[str, Any],
        llm_configured: bool,
    ) -> dict[str, dict[str, Any]]:
        """能力矩阵：每项给 available/blocking/fallback，让用户知道“现在能跑什么”。

        optional=True 的能力未配置属默认形态，不参与 ready 判定；
        optional=False 的能力缺失会把状态压到 degraded_ready（有降级路径）
        或 not_ready（静态核心不可用）。
        """
        container_blocking: list[str] = []
        if not docker.get("daemon_available"):
            container_blocking.append("docker daemon unavailable")
        if required_gaps:
            container_blocking.append(f"missing images: {', '.join(required_gaps)}")
        ts_missing = [name for name, ok in ts.get("languages", {}).items() if not ok]
        ast_blocking: list[str] = []
        if not ts.get("pack_installed"):
            ast_blocking.append("tree-sitter-language-pack not installed")
        elif not ts.get("enabled"):
            ast_blocking.append("AST lane disabled by env")
        elif ts_missing:
            ast_blocking.append(f"parsers not cached: {', '.join(ts_missing)}")
        core_blocking = [] if python_supported else ["python>=3.11 required"]
        return {
            "static_audit": {
                "available": python_supported,
                "optional": False,
                "blocking": core_blocking,
                "fallback": None,
            },
            "secret_leak_scan": {
                "available": python_supported,
                "optional": False,
                "blocking": list(core_blocking),
                "fallback": None,
            },
            "mcp_ast_analysis": {
                "available": not ast_blocking,
                "optional": False,
                "blocking": ast_blocking,
                "fallback": "regex protocol lane (lower precision)" if ast_blocking else None,
            },
            "container_verification": {
                "available": not container_blocking,
                "optional": False,
                "blocking": container_blocking,
                "fallback": "static verification only (no tool sandbox)" if container_blocking else None,
                "next_step": "vibe-sec setup" if container_blocking else None,
            },
            "llm_deep_analysis": {
                "available": llm_configured,
                "optional": True,
                "blocking": [] if llm_configured else ["VIBE_SEC_DEEPSEEK_API_KEY / DEEPSEEK_API_KEY not set"],
                "fallback": "deterministic pipeline without LLM enrichment",
            },
            "codeql_scan": {
                "available": docker.get("daemon_available") and "codeql" not in optional_gaps,
                "optional": True,
                "blocking": [] if (docker.get("daemon_available") and "codeql" not in optional_gaps) else ["codeql image not installed"],
                "next_step": "vibe-sec setup --include-codeql",
            },
        }

    def setup(
        self,
        *,
        include: Iterable[str] | None = None,
        include_codeql: bool = False,
        force: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        selected = self._selected_images(include, include_codeql)
        before = self.doctor()
        actions: list[dict[str, Any]] = []
        docker = before["docker"]
        if not docker["daemon_available"]:
            return {
                "contract_version": "vibe-sec.setup.v1",
                "status": "blocked",
                "reason": docker["error"] or "Docker daemon is unavailable",
                "selected": [item["id"] for item in selected],
                "actions": actions,
                "doctor": before,
            }
        for item in selected:
            current = self._inspect_image(item)
            if current["available"] and not force:
                actions.append({"id": item["id"], "status": "already_ready"})
                continue
            command = [
                self.docker_binary,
                "build",
                "--progress=plain",
                "-t",
                str(item["image"]),
                str((self.root / str(item["build_context"])).resolve()),
            ]
            if force:
                command.insert(2, "--pull")
            if dry_run:
                actions.append({
                    "id": item["id"], "status": "planned", "command": command,
                    "artifacts": [artifact["path"] for artifact in item.get("artifacts", [])],
                })
                continue
            dependency_failure = next((
                action for action in actions
                if action.get("id") in item.get("depends_on", [])
                and action.get("status") in {"failed", "blocked"}
            ), None)
            if dependency_failure:
                actions.append({
                    "id": item["id"], "status": "blocked",
                    "reason": f"Dependency failed: {dependency_failure['id']}",
                })
                continue
            try:
                artifacts = [self._prepare_artifact(value) for value in item.get("artifacts", [])]
            except (OSError, ValueError) as exc:
                actions.append({"id": item["id"], "status": "failed", "reason": str(exc)})
                continue
            completed = subprocess.run(
                command,
                cwd=str(self.root),
                capture_output=True,
                text=True,
                timeout=1_800,
                check=False,
            )
            accepted = self._inspect_image(item)
            status = "installed" if completed.returncode == 0 and accepted["available"] else "failed"
            failure_reason = (
                accepted["reason"]
                if completed.returncode == 0
                else (completed.stderr.strip() or f"Docker build exited with {completed.returncode}")[-2_000:]
            )
            actions.append({
                "id": item["id"],
                "status": status,
                "exit_code": completed.returncode,
                "reason": failure_reason if status == "failed" else "Image installed and accepted",
                "artifacts": artifacts,
                "log_tail": (completed.stdout + "\n" + completed.stderr)[-4_000:],
            })
        after = before if dry_run else self.doctor()
        failed = [item for item in actions if item["status"] in {"failed", "blocked"}]
        report = {
            "contract_version": "vibe-sec.setup.v1",
            "status": "planned" if dry_run else ("completed" if not failed else "partial"),
            "release": self.manifest.get("release"),
            "selected": [item["id"] for item in selected],
            "actions": actions,
            "doctor": after,
        }
        if not dry_run:
            # 解析器预热失败不阻塞镜像安装结果，仅作为附加状态报告。
            report["tree_sitter_warmup"] = tree_sitter_warmup()
            self._write_state(report)
        return report

    def _selected_images(
        self,
        include: Iterable[str] | None,
        include_codeql: bool,
    ) -> list[dict[str, Any]]:
        requested = list(dict.fromkeys(str(item) for item in (include or []) if str(item)))
        if requested:
            unknown = sorted(set(requested) - set(self.images))
            if unknown:
                raise ValueError("Unknown tool image ids: " + ", ".join(unknown))
            selected_ids = set(requested)
        else:
            selected_ids = {
                str(item["id"]) for item in self.manifest["images"] if item.get("default_install")
            }
        if include_codeql:
            selected_ids.add("codeql")
        changed = True
        while changed:
            changed = False
            for image_id in list(selected_ids):
                for dependency in self.images[image_id].get("depends_on", []):
                    if dependency not in selected_ids:
                        selected_ids.add(dependency)
                        changed = True
        return [item for item in self.manifest["images"] if item["id"] in selected_ids]

    def _inspect_image(self, item: dict[str, Any]) -> dict[str, Any]:
        requirement = ImageRequirement(
            str(item["image"]),
            set(item.get("capabilities", [])),
            str(item.get("image_version", "")),
            dict(item.get("tool_versions", {})),
        )
        result = ContainerImagePreflight(docker_binary=self.docker_binary).inspect(requirement)
        return {
            "id": item["id"],
            "default_install": bool(item.get("default_install")),
            **result.to_dict(),
        }

    def _docker_status(self) -> dict[str, Any]:
        binary = shutil.which(self.docker_binary)
        if not binary:
            return {
                "binary": None, "client_available": False, "daemon_available": False,
                "server_version": "", "error": f"Container runtime not found: {self.docker_binary}",
            }
        try:
            completed = subprocess.run(
                [self.docker_binary, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {
                "binary": binary, "client_available": True, "daemon_available": False,
                "server_version": "", "error": str(exc),
            }
        return {
            "binary": binary,
            "client_available": True,
            "daemon_available": completed.returncode == 0,
            "server_version": completed.stdout.strip() if completed.returncode == 0 else "",
            "error": "" if completed.returncode == 0 else completed.stderr.strip(),
        }

    def _prepare_artifact(self, artifact: dict[str, Any]) -> dict[str, Any]:
        target = (self.root / str(artifact["path"])).resolve()
        target.relative_to(self.root)
        target.parent.mkdir(parents=True, exist_ok=True)
        expected = str(artifact["sha256"]).lower()
        if target.is_file() and _sha256(target) == expected:
            return {"path": str(target), "status": "cached", "sha256": expected}
        offset = target.stat().st_size if target.is_file() else 0
        request = urllib.request.Request(
            str(artifact["url"]),
            headers={
                "User-Agent": "vibe-sec-installer/0.5.0",
                **({"Range": f"bytes={offset}-"} if offset else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                append = offset > 0 and getattr(response, "status", 200) == 206
                with target.open("ab" if append else "wb") as handle:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        handle.write(chunk)
        except Exception as exc:
            raise OSError(f"Artifact download failed; partial cache preserved at {target}: {exc}") from exc
        actual = _sha256(target)
        if actual != expected:
            target.unlink(missing_ok=True)
            raise ValueError(
                f"Artifact checksum mismatch for {artifact['url']}: expected {expected}, received {actual}"
            )
        return {"path": str(target), "status": "downloaded", "sha256": actual}

    def _write_state(self, report: dict[str, Any]) -> None:
        state_dir = self.root / ".vibe-sec"
        state_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": "vibe-sec.install-state.v1",
            "updated_at": datetime.now(UTC).isoformat(),
            "release": self.manifest.get("release"),
            "status": report.get("status"),
            "selected": report.get("selected", []),
            "doctor": report.get("doctor", {}),
        }
        (state_dir / "install-state.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8",
        )

    def _load_manifest(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid tool image manifest: {exc}") from exc
        if payload.get("schema_version") != "vibe-sec.tool-images.v1":
            raise ValueError("Unsupported tool image manifest schema")
        if not isinstance(payload.get("images"), list) or not payload["images"]:
            raise ValueError("Tool image manifest must contain images")
        return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
