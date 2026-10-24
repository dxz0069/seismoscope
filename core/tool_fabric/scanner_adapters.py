"""Container-backed adapters for deterministic security scanners."""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any, Dict, List, Protocol
from urllib.parse import urlparse

from ..sanitization import redact_sensitive_text, sanitize_for_persistence
from .container import ContainerProfile, ContainerRunResult, ContainerToolRunner
from .image_preflight import ContainerImagePreflight, ImagePreflightResult, ImageRequirement
from .models import (
    ToolAdapterError,
    ToolExecutionStatus,
    ToolRequest,
    ToolResult,
    ToolRiskClass,
    ToolSignal,
    ToolSpec,
)
from .registry import ToolRegistry


class ContainerRunner(Protocol):
    async def run(self, command, *, project_root, profile, timeout_seconds, env=None) -> ContainerRunResult:
        ...


class SemgrepAdapter:
    spec = ToolSpec(
        name="semgrep_scan",
        description="Run the approved Semgrep rule pack against a bounded project path and return normalized findings.",
        capability="scanner.sast",
        risk_class=ToolRiskClass.SCANNER,
        timeout_seconds=180,
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Project-relative file or directory."},
                "rule_pack": {"type": "string", "enum": ["default", "secrets", "web", "agent"]},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 500},
            },
        },
    )
    RULE_PACKS = {
        "default": "/opt/vibe-sec/rules/semgrep/default",
        "secrets": "/opt/vibe-sec/rules/semgrep/secrets",
        "web": "/opt/vibe-sec/rules/semgrep/web",
        "agent": "/opt/vibe-sec/rules/semgrep/agent",
    }

    def __init__(self, runner: ContainerRunner, profile: ContainerProfile):
        self.runner = runner
        self.profile = profile

    async def execute(self, request: ToolRequest, context: Any) -> ToolResult:
        relative = _container_path(request.arguments.get("path", "."))
        rule_pack = str(request.arguments.get("rule_pack", "default"))
        if rule_pack not in self.RULE_PACKS:
            raise ValueError(f"Unsupported Semgrep rule pack: {rule_pack}")
        limit = _limit(request.arguments.get("max_results", 200), 500)
        command = [
            "semgrep", "scan", "--json", "--metrics", "off", "--disable-version-check",
            "--config", self.RULE_PACKS[rule_pack], relative,
        ]
        run = await self.runner.run(
            command,
            project_root=str(context.project_root),
            profile=self.profile,
            timeout_seconds=self.spec.timeout_seconds,
            env={"HOME": "/tmp"},
        )
        artifact = context.artifact_store.put_text(
            redact_sensitive_text(run.stdout or run.stderr or run.error or ""),
            producer=self.spec.name,
            artifact_type="scanner_output",
            file_name="semgrep.json",
            media_type="application/json",
            metadata={"status": run.status, "exit_code": run.exit_code},
        )
        if run.status != "completed":
            raise _scanner_failure("semgrep", run, artifact)
        try:
            payload = _parse_json(run.stdout, "Semgrep")
        except ValueError as exc:
            raise _scanner_failure("semgrep", run, artifact, error=str(exc)) from exc
        signals = []
        for item in list(payload.get("results", []))[:limit]:
            extra = item.get("extra") or {}
            start = item.get("start") or {}
            end = item.get("end") or {}
            raw_rule_id = str(item.get("check_id") or "semgrep")
            signals.append(ToolSignal(
                kind="sast_finding",
                summary=str(extra.get("message") or item.get("check_id") or "Semgrep finding"),
                severity=_semgrep_severity(extra.get("severity")),
                confidence=0.8,
                rule_id=_semgrep_rule_id(raw_rule_id, rule_pack),
                file_path=_host_path(item.get("path")),
                line_start=_optional_int(start.get("line")),
                line_end=_optional_int(end.get("line")),
                artifact_refs=[artifact.artifact_id],
                metadata={
                    "scanner": "semgrep",
                    "rule_pack": rule_pack,
                    "raw_rule_id": raw_rule_id,
                    "metadata": extra.get("metadata") or {},
                },
            ))
        return ToolResult(
            output={
                "scanner": "semgrep",
                "signal_count": len(signals),
                "signals": [item.to_dict() for item in signals],
                "errors": payload.get("errors", []),
                "artifact_ref": artifact.artifact_id,
            },
            signals=signals,
            artifacts=[artifact],
        )


class GitleaksAdapter:
    spec = ToolSpec(
        name="gitleaks_scan",
        description="Run Gitleaks against a bounded project path and return redacted secret-location signals.",
        capability="scanner.secrets",
        risk_class=ToolRiskClass.SCANNER,
        timeout_seconds=120,
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Project-relative file or directory."},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 500},
            },
        },
    )

    def __init__(self, runner: ContainerRunner, profile: ContainerProfile):
        self.runner = runner
        self.profile = profile

    async def execute(self, request: ToolRequest, context: Any) -> ToolResult:
        relative = _container_path(request.arguments.get("path", "."))
        limit = _limit(request.arguments.get("max_results", 200), 500)
        command = [
            "gitleaks", "detect", "--no-banner", "--no-git", "--exit-code", "0",
            "--report-format", "json", "--report-path", "/dev/stdout", "--source", relative,
        ]
        run = await self.runner.run(
            command,
            project_root=str(context.project_root),
            profile=self.profile,
            timeout_seconds=self.spec.timeout_seconds,
        )
        artifact = context.artifact_store.put_text(
            _redact_gitleaks_output(run.stdout or run.stderr or run.error or ""),
            producer=self.spec.name,
            artifact_type="scanner_output_sensitive",
            file_name="gitleaks.json",
            media_type="application/json",
            metadata={
                "status": run.status,
                "exit_code": run.exit_code,
                "sensitive": True,
                "redacted": True,
            },
        )
        if run.status != "completed":
            raise _scanner_failure("gitleaks", run, artifact)
        try:
            payload = _parse_json(run.stdout or "[]", "Gitleaks")
        except ValueError as exc:
            raise _scanner_failure("gitleaks", run, artifact, error=str(exc)) from exc
        findings = payload if isinstance(payload, list) else list(payload.get("findings", []))
        signals = []
        for item in findings[:limit]:
            signals.append(ToolSignal(
                kind="secret_finding",
                summary=str(item.get("Description") or item.get("RuleID") or "Potential secret"),
                severity="high",
                confidence=0.9,
                rule_id=str(item.get("RuleID") or "gitleaks"),
                file_path=_host_path(item.get("File")),
                line_start=_optional_int(item.get("StartLine")),
                line_end=_optional_int(item.get("EndLine")),
                artifact_refs=[artifact.artifact_id],
                metadata={
                    "scanner": "gitleaks",
                    "fingerprint": item.get("Fingerprint"),
                    "secret_redacted": True,
                },
            ))
        return ToolResult(
            output={
                "scanner": "gitleaks",
                "signal_count": len(signals),
                "signals": [item.to_dict() for item in signals],
                "artifact_ref": artifact.artifact_id,
                "secret_values_exposed": False,
            },
            signals=signals,
            artifacts=[artifact],
        )


class BanditAdapter:
    spec = ToolSpec(
        name="bandit_scan",
        description="Run Bandit against bounded Python source and return normalized Python security signals.",
        capability="scanner.sast.python",
        risk_class=ToolRiskClass.SCANNER,
        timeout_seconds=180,
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 500},
            },
        },
    )

    def __init__(self, runner: ContainerRunner, profile: ContainerProfile):
        self.runner = runner
        self.profile = profile

    async def execute(self, request: ToolRequest, context: Any) -> ToolResult:
        relative = _container_path(request.arguments.get("path", "."))
        limit = _limit(request.arguments.get("max_results", 200), 500)
        run = await self.runner.run(
            ["bandit", "-r", relative, "-f", "json", "--exit-zero", "-q"],
            project_root=str(context.project_root),
            profile=self.profile,
            timeout_seconds=self.spec.timeout_seconds,
            env={"HOME": "/tmp"},
        )
        artifact = _scanner_artifact(context, self.spec.name, "bandit", run)
        if run.status != "completed":
            raise _scanner_failure("bandit", run, artifact)
        try:
            payload = _parse_json(run.stdout or "{}", "Bandit")
        except ValueError as exc:
            raise _scanner_failure("bandit", run, artifact, error=str(exc)) from exc
        signals = []
        for item in list(payload.get("results", []) or [])[:limit]:
            signals.append(ToolSignal(
                kind="sast_finding",
                summary=str(item.get("issue_text") or item.get("test_name") or "Bandit finding"),
                severity=_normalized_severity(item.get("issue_severity")),
                confidence=_confidence(item.get("issue_confidence")),
                rule_id=str(item.get("test_id") or item.get("test_name") or "bandit"),
                file_path=_host_path(item.get("filename")),
                line_start=_optional_int(item.get("line_number")),
                line_end=_optional_int((item.get("line_range") or [None])[-1]),
                artifact_refs=[artifact.artifact_id],
                metadata={
                    "scanner": "bandit",
                    "test_name": item.get("test_name"),
                    "more_info": item.get("more_info"),
                },
            ))
        return _scanner_result("bandit", signals, artifact, metrics=payload.get("metrics", {}))


class TrivyAdapter:
    spec = ToolSpec(
        name="trivy_filesystem_scan",
        description=(
            "Run the pinned offline Trivy filesystem profile for dependency, configuration, and secret signals."
        ),
        capability="scanner.composition",
        risk_class=ToolRiskClass.SCANNER,
        timeout_seconds=300,
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "scanners": {
                    "type": "string",
                    "enum": ["vuln", "misconfig", "secret", "vuln,misconfig,secret"],
                },
                "max_results": {"type": "integer", "minimum": 1, "maximum": 1000},
            },
        },
    )

    def __init__(self, runner: ContainerRunner, profile: ContainerProfile):
        self.runner = runner
        self.profile = profile

    async def execute(self, request: ToolRequest, context: Any) -> ToolResult:
        relative = _container_path(request.arguments.get("path", "."))
        scanners = str(request.arguments.get("scanners", "vuln,misconfig,secret"))
        if scanners not in {"vuln", "misconfig", "secret", "vuln,misconfig,secret"}:
            raise ValueError("Unsupported Trivy scanner profile")
        limit = _limit(request.arguments.get("max_results", 500), 1000)
        provenance_run = await self.runner.run(
            ["trivy", "--version", "--format", "json"],
            project_root=str(context.project_root),
            profile=self.profile,
            timeout_seconds=30,
            env={"HOME": "/tmp", "TRIVY_CACHE_DIR": "/opt/trivy-cache"},
        )
        if provenance_run.status != "completed":
            artifact = _scanner_artifact(
                context, self.spec.name, "trivy-provenance", provenance_run,
            )
            raise _scanner_failure("trivy database provenance", provenance_run, artifact)
        try:
            provenance = _parse_json(provenance_run.stdout or "{}", "Trivy version")
        except ValueError as exc:
            artifact = _scanner_artifact(
                context, self.spec.name, "trivy-provenance", provenance_run,
            )
            raise _scanner_failure(
                "trivy database provenance", provenance_run, artifact, error=str(exc),
            ) from exc
        database = dict(provenance.get("VulnerabilityDB") or {})
        if scanners in {"vuln", "vuln,misconfig,secret"} and not _valid_trivy_database(database):
            artifact = _scanner_artifact(
                context, self.spec.name, "trivy-provenance", provenance_run,
            )
            raise _scanner_failure(
                "trivy database provenance",
                provenance_run,
                artifact,
                error="Trivy vulnerability database freshness metadata is unavailable",
            )
        run = await self.runner.run(
            [
                "trivy", "fs", "--format", "json", "--scanners", scanners,
                "--offline-scan", "--skip-db-update", "--skip-check-update",
                "--exit-code", "0", relative,
            ],
            project_root=str(context.project_root),
            profile=self.profile,
            timeout_seconds=self.spec.timeout_seconds,
            env={"HOME": "/tmp", "TRIVY_CACHE_DIR": "/opt/trivy-cache"},
        )
        provenance_summary = {
            "scanner_version": provenance.get("Version"),
            "database": database,
        }
        artifact = _scanner_artifact(
            context, self.spec.name, "trivy", run, metadata=provenance_summary,
        )
        if run.status != "completed":
            raise _scanner_failure("trivy", run, artifact)
        try:
            payload = _parse_json(run.stdout or "{}", "Trivy")
        except ValueError as exc:
            raise _scanner_failure("trivy", run, artifact, error=str(exc)) from exc
        signals: List[ToolSignal] = []
        for result in list(payload.get("Results", []) or []):
            target = _host_path(result.get("Target"))
            for item in list(result.get("Vulnerabilities", []) or []):
                signals.append(ToolSignal(
                    kind="dependency_vulnerability",
                    summary=str(item.get("Title") or item.get("VulnerabilityID") or "Trivy vulnerability"),
                    severity=_normalized_severity(item.get("Severity")),
                    confidence=0.9,
                    rule_id=str(item.get("VulnerabilityID") or "trivy-vulnerability"),
                    file_path=target or None,
                    artifact_refs=[artifact.artifact_id],
                    metadata={
                        "scanner": "trivy", "package": item.get("PkgName"),
                        "installed_version": item.get("InstalledVersion"),
                        "fixed_version": item.get("FixedVersion"), "class": result.get("Class"),
                        "database": database,
                    },
                ))
            for item in list(result.get("Misconfigurations", []) or []):
                cause = dict(item.get("CauseMetadata") or {})
                signals.append(ToolSignal(
                    kind="configuration_finding",
                    summary=str(item.get("Title") or item.get("Message") or "Trivy misconfiguration"),
                    severity=_normalized_severity(item.get("Severity")),
                    confidence=0.85,
                    rule_id=str(item.get("ID") or item.get("AVDID") or "trivy-misconfiguration"),
                    file_path=target or None,
                    line_start=_optional_int(cause.get("StartLine")),
                    line_end=_optional_int(cause.get("EndLine")),
                    artifact_refs=[artifact.artifact_id],
                    metadata={"scanner": "trivy", "resolution": item.get("Resolution")},
                ))
            for item in list(result.get("Secrets", []) or []):
                signals.append(ToolSignal(
                    kind="secret_finding",
                    summary=str(item.get("Title") or item.get("RuleID") or "Trivy secret"),
                    severity=_normalized_severity(item.get("Severity") or "high"),
                    confidence=0.9,
                    rule_id=str(item.get("RuleID") or "trivy-secret"),
                    file_path=target or None,
                    line_start=_optional_int(item.get("StartLine")),
                    line_end=_optional_int(item.get("EndLine")),
                    artifact_refs=[artifact.artifact_id],
                    metadata={"scanner": "trivy", "secret_redacted": True},
                ))
            if len(signals) >= limit:
                break
        return _scanner_result(
            "trivy", signals[:limit], artifact,
            scanner_version=provenance.get("Version"), database=database,
        )


class CodeQLAdapter:
    spec = ToolSpec(
        name="codeql_database_scan",
        description="Analyze a pre-built, project-scoped CodeQL database with an approved security suite.",
        capability="scanner.sast.dataflow",
        risk_class=ToolRiskClass.SCANNER,
        timeout_seconds=600,
        input_schema={
            "type": "object",
            "properties": {
                "database_path": {"type": "string"},
                "language": {
                    "type": "string",
                    "enum": [
                        "python", "javascript-typescript", "java-kotlin", "go",
                        "c-cpp", "csharp", "ruby", "swift",
                    ],
                },
                "query_suite": {
                    "type": "string",
                    "enum": ["security-extended", "security-and-quality"],
                },
                "max_results": {"type": "integer", "minimum": 1, "maximum": 1000},
            },
            "required": ["database_path", "language"],
        },
    )
    LANGUAGES = {
        "python", "javascript-typescript", "java-kotlin", "go",
        "c-cpp", "csharp", "ruby", "swift",
    }

    def __init__(self, runner: ContainerRunner, profile: ContainerProfile):
        self.runner = runner
        self.profile = profile

    async def execute(self, request: ToolRequest, context: Any) -> ToolResult:
        database = _container_path(request.arguments.get("database_path", ""))
        language = str(request.arguments.get("language", ""))
        if language not in self.LANGUAGES:
            raise ValueError("Unsupported or missing CodeQL language")
        suite = str(request.arguments.get("query_suite", "security-extended"))
        if suite not in {"security-extended", "security-and-quality"}:
            raise ValueError("Unsupported CodeQL query suite")
        limit = _limit(request.arguments.get("max_results", 500), 1000)
        suite_path = f"/opt/vibe-sec/codeql-suites/{language}-{suite}.qls"
        run = await self.runner.run(
            [
                "codeql", "database", "analyze", database, suite_path,
                "--format=sarif-latest", "--output=/dev/stdout", "--threads=0",
            ],
            project_root=str(context.project_root),
            profile=self.profile,
            timeout_seconds=self.spec.timeout_seconds,
            env={"HOME": "/tmp"},
        )
        artifact = _scanner_artifact(context, self.spec.name, "codeql", run)
        if run.status != "completed":
            raise _scanner_failure("codeql", run, artifact)
        try:
            payload = _parse_json(run.stdout or "{}", "CodeQL")
        except ValueError as exc:
            raise _scanner_failure("codeql", run, artifact, error=str(exc)) from exc
        signals: List[ToolSignal] = []
        for sarif_run in list(payload.get("runs", []) or []):
            for item in list(sarif_run.get("results", []) or []):
                location = ((item.get("locations") or [{}])[0].get("physicalLocation") or {})
                region = dict(location.get("region") or {})
                uri = (location.get("artifactLocation") or {}).get("uri")
                message = item.get("message") or {}
                signals.append(ToolSignal(
                    kind="dataflow_finding",
                    summary=str(message.get("text") or item.get("ruleId") or "CodeQL finding"),
                    severity=_sarif_severity(item.get("level")),
                    confidence=0.9,
                    rule_id=str(item.get("ruleId") or "codeql"),
                    file_path=_host_path(uri) or None,
                    line_start=_optional_int(region.get("startLine")),
                    line_end=_optional_int(region.get("endLine")),
                    artifact_refs=[artifact.artifact_id],
                    metadata={
                        "scanner": "codeql", "language": language, "query_suite": suite,
                        "properties": item.get("properties") or {},
                    },
                ))
                if len(signals) >= limit:
                    break
        return _scanner_result(
            "codeql", signals, artifact, language=language, query_suite=suite,
        )


class NucleiAdapter:
    spec = ToolSpec(
        name="nuclei_service_scan",
        description=(
            "Run an explicitly authorized, rate-limited Nuclei profile against one approved HTTP(S) target."
        ),
        capability="scanner.active.http",
        risk_class=ToolRiskClass.ACTIVE,
        required_permissions=["network:authorized-target", "active_scan"],
        timeout_seconds=300,
        input_schema={
            "type": "object",
            "properties": {
                "target_url": {"type": "string"},
                "template_profile": {"type": "string", "enum": ["safe-http", "exposures", "misconfiguration"]},
                "severity": {"type": "string", "enum": ["critical,high", "critical,high,medium"]},
                "rate_limit": {"type": "integer", "minimum": 1, "maximum": 20},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 200},
            },
            "required": ["target_url"],
        },
    )
    PROFILES = {
        "safe-http": "/opt/vibe-sec/nuclei/safe-http",
        "exposures": "/opt/vibe-sec/nuclei/exposures",
        "misconfiguration": "/opt/vibe-sec/nuclei/misconfiguration",
    }

    def __init__(self, runner: ContainerRunner, profile: ContainerProfile):
        self.runner = runner
        self.profile = profile

    async def execute(self, request: ToolRequest, context: Any) -> ToolResult:
        target = str(request.arguments.get("target_url", ""))
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Nuclei target_url must be an absolute HTTP(S) URL")
        template_profile = str(request.arguments.get("template_profile", "safe-http"))
        if template_profile not in self.PROFILES:
            raise ValueError("Unsupported Nuclei template profile")
        severity = str(request.arguments.get("severity", "critical,high"))
        if severity not in {"critical,high", "critical,high,medium"}:
            raise ValueError("Unsupported Nuclei severity profile")
        rate = _limit(request.arguments.get("rate_limit", 5), 20)
        limit = _limit(request.arguments.get("max_results", 100), 200)
        run = await self.runner.run(
            [
                "nuclei", "-u", target, "-jsonl", "-silent", "-no-interactsh",
                "-disable-update-check",
                "-severity", severity, "-rate-limit", str(rate),
                "-t", self.PROFILES[template_profile],
            ],
            project_root=str(context.project_root),
            profile=self.profile,
            timeout_seconds=self.spec.timeout_seconds,
        )
        artifact = _scanner_artifact(context, self.spec.name, "nuclei", run)
        if run.status != "completed":
            raise _scanner_failure("nuclei", run, artifact)
        signals = []
        for line in run.stdout.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = dict(item.get("info") or {})
            signals.append(ToolSignal(
                kind="active_http_finding",
                summary=str(info.get("name") or item.get("template-id") or "Nuclei finding"),
                severity=_normalized_severity(info.get("severity")),
                confidence=0.85,
                rule_id=str(item.get("template-id") or "nuclei"),
                artifact_refs=[artifact.artifact_id],
                metadata={
                    "scanner": "nuclei", "matched_at": item.get("matched-at"),
                    "target_url": target, "template_profile": template_profile,
                },
            ))
            if len(signals) >= limit:
                break
        return _scanner_result("nuclei", signals, artifact)


def register_container_scanners(
    registry: ToolRegistry,
    *,
    runner: ContainerRunner | None = None,
    profile: ContainerProfile | None = None,
    trivy_profile: ContainerProfile | None = None,
    codeql_profile: ContainerProfile | None = None,
    preflight: ContainerImagePreflight | None = None,
    verify_images: bool | None = None,
) -> Dict[str, Dict[str, object]]:
    custom_runner = runner is not None
    runner = runner or ContainerToolRunner()
    profile = profile or ContainerProfile()
    trivy_profile = trivy_profile or ContainerProfile(
        image="vibe-sec-trivy:latest", read_only_root=False,
    )
    codeql_profile = codeql_profile or ContainerProfile(
        image="vibe-sec-codeql:latest", memory_limit="2g", cpu_limit="2.0",
    )
    verify = not custom_runner if verify_images is None else bool(verify_images)
    checker = preflight or ContainerImagePreflight()
    requirements = {
        "base": ImageRequirement(
            profile.image, {"semgrep", "gitleaks", "bandit"}, "2026.07.22",
            {"semgrep": "1.99.0", "gitleaks": "8.21.2", "bandit": "1.8.0"},
        ),
        "trivy": ImageRequirement(
            trivy_profile.image,
            {"trivy-fs-vuln", "trivy-fs-misconfig", "trivy-fs-secret"},
            "0.58.2",
        ),
        "codeql": ImageRequirement(
            codeql_profile.image, {"codeql-database-analyze"}, "2.26.1",
        ),
    }
    accepted = {
        name: checker.inspect(requirement) if verify else _unchecked_image(requirement)
        for name, requirement in requirements.items()
    }
    if accepted["base"].available:
        registry.register(SemgrepAdapter(runner, profile))
        registry.register(GitleaksAdapter(runner, profile))
        registry.register(BanditAdapter(runner, profile))
    if accepted["trivy"].available:
        registry.register(TrivyAdapter(runner, trivy_profile))
    if accepted["codeql"].available:
        registry.register(CodeQLAdapter(runner, codeql_profile))
    return {name: result.to_dict() for name, result in accepted.items()}


def register_active_scanners(
    registry: ToolRegistry,
    *,
    runner: ContainerRunner | None = None,
    profile: ContainerProfile | None = None,
    preflight: ContainerImagePreflight | None = None,
    verify_image: bool | None = None,
) -> Dict[str, object]:
    """Trusted control-plane hook; callers must also configure target/network policy."""
    custom_runner = runner is not None
    runner = runner or ContainerToolRunner()
    profile = profile or ContainerProfile(image="vibe-sec-nuclei:latest", network="bridge")
    verify = not custom_runner if verify_image is None else bool(verify_image)
    requirement = ImageRequirement(profile.image, {"nuclei-curated-http"}, "3.11.0")
    result = (preflight or ContainerImagePreflight()).inspect(requirement) if verify else _unchecked_image(requirement)
    if result.available:
        registry.register(NucleiAdapter(runner, profile))
    return result.to_dict()


def _container_path(value: Any) -> str:
    raw = str(value or ".").replace("\\", "/").strip().lstrip("/")
    if raw in {"", "."}:
        return "/workspace"
    path = PurePosixPath(raw)
    if ".." in path.parts:
        raise ValueError("Scanner path escapes workspace")
    return "/workspace/" + str(path)


def _host_path(value: Any) -> str:
    raw = str(value or "").replace("\\", "/")
    if raw.startswith("/workspace/"):
        return raw[len("/workspace/"):]
    return raw.lstrip("./")


def _parse_json(value: str, scanner: str):
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{scanner} returned invalid JSON: {exc}") from exc


def _redact_gitleaks_output(value: str) -> str:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return redact_sensitive_text(value)
    return json.dumps(sanitize_for_persistence(parsed), ensure_ascii=False, indent=2)


def _semgrep_severity(value: Any) -> str:
    return {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(str(value).upper(), "medium")


def _semgrep_rule_id(value: str, rule_pack: str) -> str:
    prefix = f"opt.vibe-sec.rules.semgrep.{rule_pack}."
    return value[len(prefix):] if value.startswith(prefix) else value


def _optional_int(value: Any):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _limit(value: Any, maximum: int) -> int:
    try:
        return max(1, min(maximum, int(value)))
    except (TypeError, ValueError):
        return min(200, maximum)


def _normalized_severity(value: Any) -> str:
    normalized = str(value or "medium").lower()
    return normalized if normalized in {"critical", "high", "medium", "low", "info"} else "medium"


def _confidence(value: Any) -> float:
    return {"high": 0.9, "medium": 0.75, "low": 0.6}.get(str(value or "").lower(), 0.7)


def _sarif_severity(value: Any) -> str:
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(
        str(value or "warning").lower(), "medium",
    )


def _scanner_artifact(
    context: Any,
    producer: str,
    scanner: str,
    run: ContainerRunResult,
    *,
    metadata: Dict[str, Any] | None = None,
):
    raw = run.stdout or run.stderr or run.error or ""
    try:
        persisted = json.dumps(
            sanitize_for_persistence(json.loads(raw)), ensure_ascii=False, indent=2,
        )
    except json.JSONDecodeError:
        persisted = redact_sensitive_text(raw)
    return context.artifact_store.put_text(
        persisted,
        producer=producer,
        artifact_type="scanner_output",
        file_name=f"{scanner}.json",
        media_type="application/json",
        metadata={"status": run.status, "exit_code": run.exit_code, **(metadata or {})},
    )


def _scanner_result(scanner: str, signals: List[ToolSignal], artifact: Any, **extra: Any) -> ToolResult:
    return ToolResult(
        output={
            "scanner": scanner,
            "signal_count": len(signals),
            "signals": [item.to_dict() for item in signals],
            "artifact_ref": artifact.artifact_id,
            **extra,
        },
        signals=signals,
        artifacts=[artifact],
    )


def _scanner_failure(
    scanner: str,
    run: ContainerRunResult,
    artifact,
    *,
    error: str | None = None,
) -> ToolAdapterError:
    message = error or run.error or run.stderr or f"{scanner.title()} execution failed"
    status = (
        ToolExecutionStatus.TIMED_OUT
        if run.status == "timed_out"
        else ToolExecutionStatus.FAILED
    )
    return ToolAdapterError(
        message,
        status=status,
        result=ToolResult(
            output={
                "scanner": scanner,
                "scanner_status": run.status,
                "exit_code": run.exit_code,
                "output_truncated": run.output_truncated,
                "artifact_ref": artifact.artifact_id,
            },
            artifacts=[artifact],
        ),
    )


def _valid_trivy_database(value: Dict[str, Any]) -> bool:
    return bool(
        value.get("Version")
        and value.get("UpdatedAt")
        and value.get("DownloadedAt")
    )


def _unchecked_image(requirement: ImageRequirement) -> ImagePreflightResult:
    return ImagePreflightResult(
        requirement.image,
        True,
        set(requirement.capabilities),
        requirement.version,
        reason="Image preflight explicitly bypassed for a custom runner",
        tool_versions=dict(requirement.tool_versions),
    )
