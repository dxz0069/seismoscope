import asyncio
from types import SimpleNamespace

import agents.verification_agent as verification_module
from agents.verification_agent import VerificationAgent
from core.runtime.browser_executor import BrowserExecutionResult
from core.runtime.browser_executor import PlaywrightExecutor


def test_browser_verification_blocks_non_loopback_target_before_playwright():
    executor = PlaywrightExecutor(allow_non_loopback=False)
    result = asyncio.run(executor.execute_xss_controls(
        url="https://example.com/form",
        selector="#input",
        positive_payload="<img src=x onerror=alert(1)>",
        negative_payload="hello",
    ))

    assert result.success is False
    assert result.status == "blocked"
    assert "loopback" in result.error


def test_legacy_xss_api_never_treats_dom_reflection_as_proof():
    result = asyncio.run(PlaywrightExecutor().verify_xss_vulnerability(
        "http://127.0.0.1:8000", "<b>reflected</b>",
    ))

    assert result["verified"] is False
    assert result["status"] == "needs_evidence"


def _service_backed_finding():
    return {
        "id": "finding-xss-service",
        "vulnerability_type": "xss",
        "verification_plan": {
            "browser": {
                "selector": "#input",
                "positive_payload": "<img src=x onerror=alert(1)>",
                "negative_payload": "hello",
                "service": {
                    "authorized": True,
                    "image": "python:3.12-slim",
                    "command": ["python", "-m", "http.server", "8080"],
                    "container_port": 8080,
                },
            },
        },
    }


def test_browser_service_plan_requires_trusted_control_plane_authorization(tmp_path):
    evidence = asyncio.run(VerificationAgent()._browser_verification(
        str(tmp_path),
        _service_backed_finding(),
    ))

    assert evidence.success is False
    assert evidence.outcome == "unavailable"
    assert "trusted control plane" in evidence.description


def test_browser_service_lifecycle_is_used_and_cleaned_up(monkeypatch, tmp_path):
    events = []

    class FakeServiceRunner:
        async def start(self, spec, *, project_root):
            events.append(("start", project_root, spec.image))
            return SimpleNamespace(
                ready=True,
                status="ready",
                base_url="http://127.0.0.1:49152",
                health_url="http://127.0.0.1:49152/",
                logs="",
            )

        async def logs(self, handle):
            events.append(("logs", handle.status))
            return "service-ready"

        async def stop(self, handle):
            events.append(("stop", handle.status))
            handle.status = "stopped"

    class FakePlaywrightExecutor:
        async def execute_xss_controls(self, **kwargs):
            events.append(("browser", kwargs["url"]))
            return BrowserExecutionResult(
                True,
                kwargs["url"],
                status="completed",
                predicate_satisfied=True,
                predicate="positive marker and negative control",
            )

    monkeypatch.setattr(verification_module, "ContainerServiceRunner", FakeServiceRunner)
    monkeypatch.setattr(verification_module, "PlaywrightExecutor", FakePlaywrightExecutor)

    evidence = asyncio.run(VerificationAgent()._browser_verification(
        str(tmp_path),
        _service_backed_finding(),
        service_authorization={"allow_service_start": True},
    ))

    assert evidence.success is True
    assert events == [
        ("start", str(tmp_path), "python:3.12-slim"),
        ("browser", "http://127.0.0.1:49152/"),
        ("logs", "ready"),
        ("stop", "ready"),
    ]
    assert evidence.data["service"]["status"] == "stopped"
    assert evidence.data["service"]["logs"] == "service-ready"
