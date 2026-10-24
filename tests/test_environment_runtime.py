import asyncio

import pytest

from core.verification.environment_runtime import (
    ContainerEnvironmentRunner,
    ReproductionEnvironmentPlan,
)


def _plan():
    return ReproductionEnvironmentPlan.from_dict({
        "target_service": "app",
        "services": [
            {
                "name": "app",
                "image": "python:3.12-slim",
                "command": ["python", "app.py"],
                "container_port": 8000,
                "depends_on": ["db"],
                "environment": {"DB_HOST": "db"},
            },
            {
                "name": "db",
                "image": "postgres:16-alpine",
                "command": ["postgres"],
                "health_command": ["pg_isready"],
            },
        ],
    })


def test_environment_plan_orders_dependencies_and_rejects_cycles():
    assert [item.name for item in _plan().ordered_services()] == ["db", "app"]

    with pytest.raises(ValueError, match="cycle"):
        ReproductionEnvironmentPlan.from_dict({
            "target_service": "app",
            "services": [
                {
                    "name": "app",
                    "image": "python:3.12-slim",
                        "command": ["python", "app.py"],
                        "container_port": 8000,
                        "depends_on": ["db"],
                },
                {
                    "name": "db",
                    "image": "postgres:16-alpine",
                    "command": ["postgres"],
                    "depends_on": ["app"],
                },
            ],
        })


def test_environment_runner_uses_internal_network_single_loopback_target_and_cleanup(tmp_path):
    class FakeRunner(ContainerEnvironmentRunner):
        def __init__(self):
            super().__init__()
            self.commands = []

        async def _run(self, command, *, timeout):
            self.commands.append(list(command))
            return 0, "ok", ""

        async def _wait_for_service(self, spec, container_name, health_url, timeout_seconds):
            self.commands.append(["wait", spec.name, health_url])
            return True

    runner = FakeRunner()

    async def lifecycle():
        handle = await runner.start(_plan(), project_root=str(tmp_path))
        assert handle.ready
        assert list(handle.containers) == ["db", "app"]
        assert handle.base_url == "http://app:8000"
        await runner.stop(handle)
        return handle

    handle = asyncio.run(lifecycle())
    create = runner.commands[0]
    docker_runs = [item for item in runner.commands if len(item) > 1 and item[1] == "run"]
    assert "--internal" in create
    assert len(docker_runs) == 2
    assert "--publish" not in docker_runs[0]
    assert "--publish" not in docker_runs[1]
    removals = [item[-1] for item in runner.commands if item[1:4] == ["rm", "-f", item[-1]]]
    assert removals == list(reversed(list(handle.containers.values())))
    assert handle.status == "stopped"


def test_environment_plan_rejects_shell_and_multiple_published_services():
    with pytest.raises(ValueError, match="Shell"):
        ReproductionEnvironmentPlan.from_dict({
            "target_service": "app",
            "services": [{
                "name": "app",
                "image": "python:3.12-slim",
                "command": ["sh", "-c", "python app.py"],
                "container_port": 8000,
            }],
        })

    with pytest.raises(ValueError, match="cannot publish"):
        ReproductionEnvironmentPlan.from_dict({
            "target_service": "app",
            "services": [
                {
                    "name": "app", "image": "python:3.12-slim",
                    "command": ["python", "app.py"], "container_port": 8000,
                },
                {
                    "name": "db", "image": "postgres:16-alpine",
                    "command": ["postgres"], "container_port": 5432, "publish": True,
                },
            ],
        })
