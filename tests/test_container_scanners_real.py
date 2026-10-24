"""Optional real-Docker integration checks for the focused scanner image."""

import asyncio
import shutil
import subprocess
from pathlib import Path

import pytest

from core.audit.scanner_signals import ContainerScannerCollector
from core.runtime.permission_policy import PermissionPolicy
from core.tool_fabric import (
    ArtifactStore,
    BanditAdapter,
    CodeQLAdapter,
    ContainerProfile,
    ContainerToolRunner,
    NucleiAdapter,
    ToolGateway,
    ToolRegistry,
    ToolRequest,
    TrivyAdapter,
)
from core.verification import (
    ContainerEnvironmentRunner,
    EnvironmentServiceSpec,
    ReproductionEnvironmentPlan,
)


def _image_available(image: str = "vibe-sec-tools:latest") -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        completed = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _running_tool_containers() -> set[str]:
    completed = subprocess.run(
        [
            "docker", "ps", "--filter", "ancestor=vibe-sec-tools:latest",
            "--format", "{{.ID}}",
        ],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return {item.strip() for item in completed.stdout.splitlines() if item.strip()}


def _gateway(tmp_path: Path, adapter) -> ToolGateway:
    registry = ToolRegistry()
    registry.register(adapter)
    return ToolGateway(
        registry,
        project_root=str(tmp_path),
        artifact_store=ArtifactStore(str(tmp_path / "artifacts"), session_id="real-scanners"),
        policy=PermissionPolicy(allow_network_access=False, allow_file_write=False),
    )


@pytest.mark.skipif(not _image_available(), reason="focused scanner image is not available")
def test_real_focused_container_runs_semgrep_and_gitleaks():
    project = Path(__file__).parent / "fixtures"
    collector = ContainerScannerCollector(str(project))

    web = asyncio.run(collector.collect("web_audit"))
    secrets = asyncio.run(collector.collect("secrets_audit"))

    assert web.executions[0]["status"] == "completed"
    assert secrets.executions[0]["status"] == "completed"
    assert web.signals
    assert secrets.signals
    assert web.artifact_refs
    assert secrets.artifact_refs
    assert web.gaps == []
    assert secrets.gaps == []


@pytest.mark.skipif(not _image_available(), reason="focused scanner image is not available")
def test_real_focused_container_covers_python_javascript_typescript_and_agent_rules():
    project = Path(__file__).parent / "container_fixtures" / "multilang"
    before = _running_tool_containers()
    collector = ContainerScannerCollector(str(project))

    web = asyncio.run(collector.collect("web_audit"))
    agent = asyncio.run(collector.collect("agent_audit"))

    web_rules = {item["rule_id"] for item in web.signals}
    agent_rules = {item["rule_id"] for item in agent.signals}
    assert "vibe-sec.python.command-injection-shell" in web_rules
    assert "vibe-sec.python.dynamic-sql" in web_rules
    assert "vibe-sec.javascript.unsafe-html" in web_rules
    assert {item["file_path"] for item in web.signals} >= {"browser.js", "browser.ts", "web.py"}
    assert "vibe-sec.agent.prompt-concatenation-python" in agent_rules
    assert "vibe-sec.agent.unbounded-shell-tool-python" in agent_rules
    assert web.gaps == []
    assert agent.gaps == []
    assert _running_tool_containers() == before


@pytest.mark.skipif(not _image_available(), reason="focused scanner image is not available")
def test_real_bandit_normalizes_python_findings_and_artifact(tmp_path):
    project = Path(__file__).parent / "container_fixtures" / "scanners"
    gateway = _gateway(
        tmp_path,
        BanditAdapter(ContainerToolRunner(), ContainerProfile(image="vibe-sec-tools:latest")),
    )
    gateway.project_root = project.resolve()

    result = asyncio.run(gateway.execute(ToolRequest("bandit_scan", {"path": "."})))

    assert result.status.value == "completed"
    assert "B602" in {item.rule_id for item in result.signals}
    assert result.artifacts[0].sha256
    assert Path(result.artifacts[0].path).is_file()


@pytest.mark.skipif(
    not _image_available("vibe-sec-trivy:latest"),
    reason="offline Trivy image is not available",
)
def test_real_trivy_uses_offline_database_and_records_freshness(tmp_path):
    project = Path(__file__).parent / "container_fixtures" / "scanners"
    gateway = _gateway(
        tmp_path,
        TrivyAdapter(ContainerToolRunner(), ContainerProfile(
            image="vibe-sec-trivy:latest", read_only_root=False,
        )),
    )
    gateway.project_root = project.resolve()

    result = asyncio.run(gateway.execute(ToolRequest(
        "trivy_filesystem_scan", {"path": ".", "scanners": "vuln"},
    )))

    assert result.status.value == "completed"
    assert result.output["database"]["Version"] == 2
    assert result.output["database"]["UpdatedAt"]
    assert result.output["database"]["DownloadedAt"]
    assert result.artifacts[0].metadata["database"]["DownloadedAt"]
    assert any(item.kind == "dependency_vulnerability" for item in result.signals)


@pytest.mark.skipif(
    not _image_available("vibe-sec-nuclei:latest") or not _image_available("python:3.12-slim"),
    reason="Nuclei or Python fixture image is not available",
)
def test_real_nuclei_scans_only_authorized_internal_service_and_cleans_up(tmp_path):
    project = Path(__file__).parent / "container_fixtures"

    async def run_test():
        environment = ContainerEnvironmentRunner()
        plan = ReproductionEnvironmentPlan(
            services=[EnvironmentServiceSpec(
                name="app",
                image="python:3.12-slim",
                command=["python", "/workspace/nuclei_service.py"],
                container_port=8000,
            )],
            target_service="app",
        )
        handle = await environment.start(plan, project_root=str(project))
        assert handle.ready, handle.error
        try:
            registry = ToolRegistry()
            registry.register(NucleiAdapter(
                ContainerToolRunner(),
                ContainerProfile(image="vibe-sec-nuclei:latest", network=handle.network_name),
            ))
            gateway = ToolGateway(
                registry,
                project_root=str(project),
                artifact_store=ArtifactStore(str(tmp_path / "artifacts"), session_id="real-nuclei"),
                policy=PermissionPolicy(
                    allowed_domains=["app"], allow_network_access=True, allow_file_write=False,
                ),
            )
            result = await gateway.execute(ToolRequest(
                "nuclei_service_scan",
                {
                    "target_url": handle.base_url,
                    "template_profile": "safe-http",
                    "severity": "critical,high,medium",
                    "rate_limit": 2,
                },
            ))
            assert result.status.value == "completed"
            assert "vibe-sec-fixture-header" in {item.rule_id for item in result.signals}
            assert result.artifacts[0].sha256
        finally:
            await environment.stop(handle)
        inspect = subprocess.run(
            ["docker", "network", "inspect", handle.network_name], capture_output=True, check=False,
        )
        assert inspect.returncode != 0

    asyncio.run(run_test())


@pytest.mark.skipif(
    not _image_available("vibe-sec-codeql:latest"),
    reason="CodeQL image is not available",
)
def test_real_codeql_analyzes_prebuilt_python_database(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text(
        "import sqlite3\n\ndef find_user(user_id):\n"
        "    db = sqlite3.connect('app.db')\n"
        "    return db.execute('SELECT * FROM users WHERE id=' + user_id).fetchall()\n",
        encoding="utf-8",
    )
    create = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none", "--memory", "2g", "--cpus", "2",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--mount", f"type=bind,source={tmp_path.resolve()},target=/workspace,rw",
            "vibe-sec-codeql:latest", "codeql", "database", "create", "/workspace/db",
            "--language=python", "--source-root=/workspace/src", "--overwrite",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert create.returncode == 0, create.stderr
    gateway = _gateway(
        tmp_path,
        CodeQLAdapter(
            ContainerToolRunner(),
            ContainerProfile(image="vibe-sec-codeql:latest", memory_limit="2g", cpu_limit="2.0"),
        ),
    )

    result = asyncio.run(gateway.execute(ToolRequest(
        "codeql_database_scan",
        {"database_path": "db", "language": "python", "query_suite": "security-extended"},
    )))

    assert result.status.value == "completed", result.error
    assert result.output["language"] == "python"
    assert result.output["query_suite"] == "security-extended"
    assert result.artifacts[0].sha256
    assert any(item.rule_id and "sql" in item.rule_id.lower() for item in result.signals)
