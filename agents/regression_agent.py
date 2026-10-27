"""Evidence-backed post-remediation regression Agent."""

from __future__ import annotations

import asyncio
import fnmatch
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone, UTC
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.agents.base import AgentConfig, AgentPattern, AgentResult, AgentType, BaseAgent
from core.remediation.skill_relay import RelayState, SkillRelayPackage
from core.remediation.tree_snapshot import diff_tree_snapshot, load_snapshot_ref
from core.runtime.docker_executor import DockerExecutor
from core.sanitization import redact_sensitive_text


@dataclass
class RegressionTestResult:
    test_id: str
    test_name: str
    test_type: str
    status: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "test_name": self.test_name,
            "test_type": self.test_type,
            "status": self.status,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class RegressionReport:
    package_id: str
    finding_id: str
    overall_status: str
    tests_run: int
    tests_passed: int
    tests_failed: int
    test_results: list[RegressionTestResult]
    summary: str
    recommendations: list[str]
    tests_skipped: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "finding_id": self.finding_id,
            "overall_status": self.overall_status,
            "tests_run": self.tests_run,
            "tests_passed": self.tests_passed,
            "tests_failed": self.tests_failed,
            "tests_skipped": self.tests_skipped,
            "test_results": [item.to_dict() for item in self.test_results],
            "summary": self.summary,
            "recommendations": self.recommendations,
            "created_at": self.created_at.isoformat(),
        }


class RegressionAgent(BaseAgent):
    SAFE_TEST_EXECUTABLES = {"python", "python.exe", "python3", "pytest", "pytest.exe", "node", "node.exe", "npm", "npm.cmd", "pnpm", "pnpm.cmd", "yarn", "yarn.cmd", "go", "go.exe", "cargo", "cargo.exe", "dotnet", "dotnet.exe", "mvn", "mvn.cmd", "gradle", "gradle.bat"}
    DENIED_EXECUTABLES = {"cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "bash", "sh", "zsh", "wsl"}

    def __init__(self, config=None, llm_service=None, tools=None, event_emitter=None):
        config = config or AgentConfig(
            name="Regression",
            agent_type=AgentType.REGRESSION,
            pattern=AgentPattern.PLAN_AND_EXECUTE,
            max_iterations=10,
        )
        super().__init__(config=config, llm_service=llm_service, tools=tools, event_emitter=event_emitter)

    async def run(self, payload: dict[str, Any]) -> AgentResult:
        packages = list(payload.get("completed_packages", []) or [])
        if not packages:
            return AgentResult.success_result(data={"regression_reports": [], "summary": {"total_reports": 0}})
        reports = []
        for raw in packages:
            package = self._dict_to_package(raw)
            reports.append(await self._run_regression_tests(
                package,
                project_path=payload.get("project_path"),
                run_project_tests=bool(payload.get("run_project_tests", False)),
                test_command=payload.get("test_command"),
                baseline_ref=payload.get("baseline_ref"),
            ))
        serialized = [item.to_dict() for item in reports]
        handoff = self.create_handoff(
            to_agent="orchestrator",
            summary=f"Regression completed for {len(reports)} remediation packages",
            work_completed=["retest controls", "project tests", "changed-tree assessment"],
            key_findings=[{
                "type": "regression_summary",
                "success": sum(item.overall_status == "success" for item in reports),
                "partial": sum(item.overall_status == "partial" for item in reports),
                "failure": sum(item.overall_status == "failure" for item in reports),
            }],
            context_refs={"regression_reports": json.dumps(serialized)},
        )
        return AgentResult.success_result(data={
            "regression_reports": serialized,
            "summary": self._generate_summary(reports),
        }, handoff=handoff)

    async def _run_regression_tests(
        self,
        package: SkillRelayPackage,
        *,
        project_path: str | None,
        run_project_tests: bool,
        test_command: Any = None,
        baseline_ref: str | None = None,
    ) -> RegressionReport:
        results = [
            self._test_retest_controls(package),
            await self._test_functionality(package, project_path, run_project_tests, test_command),
            await self._test_changed_tree(package, project_path, baseline_ref),
        ]
        for index, item in enumerate(results, 1):
            item.test_id = f"TEST-{index:03d}"
        passed = sum(item.status == "passed" for item in results)
        failed = sum(item.status == "failed" for item in results)
        skipped = sum(item.status == "skipped" for item in results)
        overall = "failure" if failed else ("partial" if skipped else "success")
        return RegressionReport(
            package.package_id,
            package.finding_id,
            overall,
            len(results),
            passed,
            failed,
            results,
            f"Regression status: {overall}; {passed} passed, {failed} failed, {skipped} skipped",
            self._recommendations(results),
            skipped,
        )

    @staticmethod
    def _test_retest_controls(package: SkillRelayPackage) -> RegressionTestResult:
        fix_result = dict(package.fix_result or {})
        evidence = fix_result.get("retest_evidence") or fix_result.get("verification_evidence")
        if fix_result.get("status") != "fixed" or not evidence:
            return RegressionTestResult(
                "TEMP", "Exploit and behavior controls", "retest_controls", "skipped",
                "No applied fix with post-fix retest evidence was supplied",
                {"required": ["fix_result.status=fixed", "retest_evidence"]},
            )
        records = evidence if isinstance(evidence, list) else list(evidence.get("items", []) or [])
        negative = [item for item in records if item.get("control_type") == "negative"]
        positive = [item for item in records if item.get("control_type") == "positive"]
        failing = [
            item for item in [*negative, *positive]
            if item.get("status") != "passed" or not RegressionAgent._has_evidence_provenance(item)
        ]
        if not negative or not positive:
            return RegressionTestResult(
                "TEMP", "Exploit and behavior controls", "retest_controls", "failed",
                "Both a negative exploit control and positive behavior control are required",
                {"negative_controls": len(negative), "positive_controls": len(positive)},
            )
        return RegressionTestResult(
            "TEMP", "Exploit and behavior controls", "retest_controls",
            "failed" if failing else "passed",
            (
                "One or more post-fix controls failed or lacked evidence provenance"
                if failing else "Exploit closure and intended behavior were both observed"
            ),
            {"records": records, "invalid_records": failing},
        )

    @staticmethod
    def _has_evidence_provenance(record: dict[str, Any]) -> bool:
        if not str(record.get("predicate", "")).strip():
            return False
        return any(
            record.get(key)
            for key in (
                "artifact_ref",
                "artifact_refs",
                "tool_execution_id",
                "execution_id",
                "trace_ref",
                "screenshot_ref",
            )
        )

    async def _test_functionality(
        self,
        package: SkillRelayPackage,
        project_path: str | None,
        enabled: bool,
        requested_command: Any,
    ) -> RegressionTestResult:
        del package
        if not enabled:
            return RegressionTestResult(
                "TEMP", "Project functionality", "project_tests", "skipped",
                "Project test execution was not enabled", {"reason": "run_project_tests is false"},
            )
        if not project_path or not Path(project_path).is_dir():
            return RegressionTestResult(
                "TEMP", "Project functionality", "project_tests", "skipped",
                "Project path is unavailable", {"reason": "missing project directory"},
            )
        command = self._normalize_test_command(requested_command) if requested_command else self._detect_test_command(Path(project_path))
        if not command:
            return RegressionTestResult(
                "TEMP", "Project functionality", "project_tests", "skipped",
                "No supported project test entry point was detected", {},
            )
        image = self._test_image(command)
        if not image:
            return RegressionTestResult(
                "TEMP", "Project functionality", "project_tests", "skipped",
                "No isolated test image is registered for the requested command",
                {"command": command},
            )
        executor = DockerExecutor(image=image, network_disabled=True, memory_limit="1g", cpu_limit="1.0")
        completed = await executor.execute_command(
            command,
            timeout=180,
            project_path=project_path,
            env_vars={
                "PYTHONDONTWRITEBYTECODE": "1",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "CI": "true",
            },
        )
        if completed.status in {"unavailable", "blocked", "timed_out"}:
            return RegressionTestResult(
                "TEMP", "Project functionality", "project_tests", "skipped",
                f"Isolated project test execution is unavailable: {completed.error or completed.status}",
                {"command": command, "image": image, "execution_status": completed.status},
            )
        return RegressionTestResult(
            "TEMP", "Project functionality", "project_tests",
            "passed" if completed.exit_code == 0 else "failed",
            "Project tests passed in the isolated container" if completed.exit_code == 0 else "Project tests failed in the isolated container",
            {
                "command": command,
                "image": image,
                "network": "none",
                "workspace": "read_only",
                "returncode": completed.exit_code,
                "stdout": redact_sensitive_text(completed.stdout[-8000:]),
                "stderr": redact_sensitive_text(completed.stderr[-8000:]),
            },
        )

    async def _test_changed_tree(
        self,
        package: SkillRelayPackage,
        project_path: str | None,
        baseline_ref: str | None,
    ) -> RegressionTestResult:
        fix_result = dict(package.fix_result or {})
        changed = list(fix_result.get("changed_files", []) or [])
        changed_source = "fix_result.changed_files" if changed else ""
        if not changed and project_path and baseline_ref:
            changed = await self._git_changed_files(project_path, baseline_ref)
            changed_source = "git_baseline" if changed else ""
        snapshot_details: dict[str, Any] = {}
        snapshot_ref = dict(package.metadata.get("baseline_snapshot_ref") or {})
        if not changed and project_path and snapshot_ref:
            try:
                snapshot = load_snapshot_ref(snapshot_ref)
                snapshot_details = diff_tree_snapshot(project_path, snapshot)
                changed = list(snapshot_details.get("changed_files", []) or [])
                changed_source = "tree_snapshot" if changed else ""
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                return RegressionTestResult(
                    "TEMP", "Changed-tree scope", "changed_tree", "failed",
                    f"Tree snapshot evidence is invalid: {exc}",
                    {"snapshot_ref": snapshot_ref, "error": str(exc)},
                )
        if not changed:
            return RegressionTestResult(
                "TEMP", "Changed-tree scope", "changed_tree", "skipped",
                "No changed files were observed from supplied, Git, or snapshot evidence",
                {"required": "fix_result.changed_files, baseline_ref, or baseline_snapshot_ref"},
            )
        normalized = [str(item).replace("\\", "/") for item in changed]
        affected = str(package.metadata.get("affected_file", "")).replace("\\", "/")
        scope = dict(package.metadata.get("change_scope") or {})
        legacy_allowed = package.patch_constraints.get("allowed_files", [])
        allowed = [
            str(item).replace("\\", "/")
            for item in (scope.get("allowed_files") or legacy_allowed or [])
        ]
        allowed_globs = [
            str(item).replace("\\", "/")
            for item in scope.get("allowed_globs", []) or []
        ]
        required = [
            str(item).replace("\\", "/")
            for item in (scope.get("required_files") or ([affected] if affected else []))
        ]
        outside = [
            item for item in normalized
            if (allowed or allowed_globs)
            and item not in allowed
            and not any(fnmatch.fnmatchcase(item, pattern) for pattern in allowed_globs)
        ]
        missing_required = [item for item in required if item not in normalized]
        missing_target = bool(missing_required)
        status = "failed" if outside or missing_target else "passed"
        message = (
            "Changed tree violates the declared remediation scope"
            if status == "failed"
            else "Changed tree includes the affected source and stays within declared scope"
        )
        return RegressionTestResult(
            "TEMP", "Changed-tree scope", "changed_tree", status, message,
            {
                "changed_files": normalized,
                "affected_file": affected,
                "required_files": required,
                "missing_required_files": missing_required,
                "allowed_files": allowed,
                "allowed_globs": allowed_globs,
                "outside_allowed_scope": outside,
                "changed_source": changed_source,
                "snapshot_diff": snapshot_details,
            },
        )

    @classmethod
    def _normalize_test_command(cls, value: Any) -> list[str] | None:
        command = list(value) if isinstance(value, (list, tuple)) else []
        if not command or not all(isinstance(item, str) and "\x00" not in item for item in command):
            return None
        executable = Path(command[0]).name.lower()
        if executable in cls.DENIED_EXECUTABLES or executable not in cls.SAFE_TEST_EXECUTABLES:
            return None
        return command

    @classmethod
    def _detect_test_command(cls, root: Path) -> list[str] | None:
        candidates = []
        if any((root / name).exists() for name in ("pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini")) or (root / "tests").is_dir():
            candidates.append(["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"])
        if (root / "package.json").is_file():
            manager = "pnpm" if (root / "pnpm-lock.yaml").exists() else ("yarn" if (root / "yarn.lock").exists() else "npm")
            candidates.append([manager, "test"])
        if (root / "go.mod").is_file():
            candidates.append(["go", "test", "./..."])
        if (root / "Cargo.toml").is_file():
            candidates.append(["cargo", "test", "--quiet"])
        if list(root.glob("*.sln")) or list(root.glob("*.csproj")):
            candidates.append(["dotnet", "test", "--nologo"])
        if (root / "pom.xml").is_file():
            candidates.append(["mvn", "test", "-q"])
        return next((item for item in candidates if shutil.which(item[0]) or Path(item[0]).is_file()), None)

    @staticmethod
    def _test_image(command: list[str]) -> str | None:
        executable = Path(command[0]).name.lower()
        python_image = os.getenv("VIBE_SEC_PYTHON_TEST_IMAGE", "").strip() or "python:3.12-slim"
        node_image = os.getenv("VIBE_SEC_NODE_TEST_IMAGE", "").strip() or "node:22-bookworm-slim"
        images = {
            "python": python_image, "python.exe": python_image,
            "python3": python_image, "pytest": python_image,
            "pytest.exe": python_image, "node": node_image, "node.exe": node_image,
            "npm": node_image, "npm.cmd": node_image, "pnpm": node_image,
            "pnpm.cmd": node_image, "yarn": node_image, "yarn.cmd": node_image,
            "go": "golang:1.23-bookworm",
            "go.exe": "golang:1.23-bookworm", "cargo": "rust:1.83-slim",
            "cargo.exe": "rust:1.83-slim", "dotnet": "mcr.microsoft.com/dotnet/sdk:8.0",
            "dotnet.exe": "mcr.microsoft.com/dotnet/sdk:8.0", "mvn": "maven:3.9-eclipse-temurin-21",
            "mvn.cmd": "maven:3.9-eclipse-temurin-21", "gradle": "gradle:8.11-jdk21",
            "gradle.bat": "gradle:8.11-jdk21",
        }
        return images.get(executable)

    @staticmethod
    async def _git_changed_files(project_path: str, baseline_ref: str) -> list[str]:
        try:
            completed = await asyncio.to_thread(
                subprocess.run,
                ["git", "diff", "--name-only", "--diff-filter=ACMR", str(baseline_ref), "--"],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        return [line.strip() for line in completed.stdout.splitlines() if completed.returncode == 0 and line.strip()]

    @staticmethod
    def _recommendations(results: list[RegressionTestResult]) -> list[str]:
        return [
            ("Investigate" if item.status == "failed" else "Collect evidence for")
            + f" {item.test_type}: {item.message}"
            for item in results if item.status in {"failed", "skipped"}
        ] or ["All configured regression predicates passed"]

    @staticmethod
    def _generate_summary(reports: list[RegressionReport]) -> dict[str, Any]:
        total = sum(item.tests_run for item in reports)
        skipped = sum(item.tests_skipped for item in reports)
        passed = sum(item.tests_passed for item in reports)
        return {
            "total_reports": len(reports),
            "success_count": sum(item.overall_status == "success" for item in reports),
            "partial_count": sum(item.overall_status == "partial" for item in reports),
            "failure_count": sum(item.overall_status == "failure" for item in reports),
            "total_tests": total,
            "total_passed": passed,
            "skipped_tests": skipped,
            "pass_rate": passed / (total - skipped) if total > skipped else 0.0,
        }

    @staticmethod
    def _dict_to_package(data: dict[str, Any]) -> SkillRelayPackage:
        try:
            state = RelayState(data.get("state", RelayState.DRAFT.value))
        except ValueError:
            state = RelayState.DRAFT
        metadata = dict(data.get("metadata", {}) or {})
        if data.get("change_scope") and not metadata.get("change_scope"):
            metadata["change_scope"] = dict(data["change_scope"])
        if data.get("baseline_snapshot_ref") and not metadata.get("baseline_snapshot_ref"):
            metadata["baseline_snapshot_ref"] = dict(data["baseline_snapshot_ref"])
        package = SkillRelayPackage(
            package_id=data.get("package_id", ""),
            finding_id=data.get("finding_id", ""),
            finding_title=data.get("finding_title", data.get("title", "")),
            finding_severity=data.get("finding_severity", data.get("severity", "medium")),
            ai_patch_prompt=data.get("ai_patch_prompt", ""),
            patch_constraints={
                item.get("type", "unknown"): item.get("description", "")
                for item in data.get("patch_constraints", [])
                if isinstance(item, dict)
            } if isinstance(data.get("patch_constraints"), list) else dict(data.get("patch_constraints", {})),
            retest_plan=list(data.get("retest_plan", []) or []),
            acceptance_criteria=list(data.get("acceptance_criteria", []) or []),
            state=state,
            fix_result=data.get("fix_result"),
            fix_summary=data.get("fix_summary"),
            fix_commit=data.get("fix_commit"),
            fix_diff=data.get("fix_diff"),
            retest_results=list(data.get("retest_results", []) or []),
            metadata=metadata,
        )
        if data.get("file_path") and not package.metadata.get("affected_file"):
            package.metadata["affected_file"] = data["file_path"]
        return package
