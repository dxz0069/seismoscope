import asyncio
import shutil
import subprocess

import pytest

from core.verification.service_runtime import ContainerServiceRunner, ServiceSpec


def test_service_spec_rejects_shell_and_privileged_port():
    with pytest.raises(ValueError, match="Shell"):
        ServiceSpec("python:3.12-slim", ["sh", "-c", "run"], 8000)
    with pytest.raises(ValueError, match="unprivileged"):
        ServiceSpec("python:3.12-slim", ["python", "app.py"], 8000, host_port=80)


def test_service_runner_blocks_non_allowlisted_image(tmp_path):
    spec = ServiceSpec("untrusted/image:latest", ["python", "app.py"], 8000)
    result = asyncio.run(ContainerServiceRunner().start(spec, project_root=str(tmp_path)))

    assert result.status == "blocked"
    assert "allowlisted" in result.error


def _docker_python_available():
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", "python:3.12-slim"],
            capture_output=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


@pytest.mark.skipif(not _docker_python_available(), reason="python container image unavailable")
def test_real_service_lifecycle_uses_loopback_health_and_cleans_up(tmp_path):
    (tmp_path / "index.html").write_text("ready", encoding="utf-8")
    runner = ContainerServiceRunner()
    spec = ServiceSpec(
        "python:3.12-slim",
        ["python", "-m", "http.server", "8080", "--bind", "0.0.0.0"],
        8080,
        startup_timeout_seconds=10,
    )

    async def lifecycle():
        handle = await runner.start(spec, project_root=str(tmp_path))
        assert handle.ready, handle.error or handle.logs
        assert handle.base_url.startswith("http://127.0.0.1:")
        await runner.stop(handle)
        return handle

    handle = asyncio.run(lifecycle())
    assert handle.status == "stopped"
