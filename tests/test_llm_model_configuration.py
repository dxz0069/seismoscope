import asyncio
import sys
from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks, HTTPException

from api import server
import core.llm_service as llm_service
from agents.audit_agent import AuditAgent, CandidateCase
from core.agents.base import AgentConfig, AgentType, Severity
from core.llm_service import (
    ConfiguredLLMService,
    DEEPSEEK_API_BASE_URL,
    DEEPSEEK_DEFAULT_MODEL,
    DeepSeekService,
    LLMResponse,
    MockLLMService,
    create_configured_llm_service,
)


@pytest.fixture(autouse=True)
def isolated_api_state(tmp_path):
    original_store_path = server.api_state_store.path
    server.configure_state_store(tmp_path / "api-state.sqlite3")
    server.clear_api_state()
    yield
    server.configure_state_store(original_store_path)


def _model_config(**overrides) -> server.ModelConfigCreate:
    payload = {
        "provider": "openai_compatible",
        "api_base": "https://llm.example.test/v1",
        "api_key": "unit-test-secret",
        "model_name": "audit-model",
        "temperature": 0.3,
        "max_tokens": 2048,
    }
    payload.update(overrides)
    return server.ModelConfigCreate(**payload)


def test_model_config_persists_but_never_returns_its_key():
    created = asyncio.run(server.create_model_config(_model_config()))

    public_payload = created.model_dump()
    assert public_payload["api_key_configured"] is True
    assert "api_key" not in public_payload

    persisted_path = server.api_state_store.path
    config_id = created.id
    server.configure_state_store(persisted_path)

    restored = server.model_configs_db[config_id]
    assert restored.api_key == "unit-test-secret"
    assert asyncio.run(server.get_model_config(config_id)).api_key_configured is True


def test_activating_a_second_chat_model_deactivates_the_first():
    first = asyncio.run(server.create_model_config(_model_config(model_name="first")))
    second = asyncio.run(server.create_model_config(_model_config(model_name="second")))

    assert asyncio.run(server.get_model_config(first.id)).is_active is False
    assert second.is_active is True
    assert server._active_chat_model_config().id == second.id


def test_llm_task_preflight_requires_active_config_or_legacy_key(monkeypatch, tmp_path):
    monkeypatch.delenv("VIBE_SEC_DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    project = asyncio.run(server.create_project(server.ProjectCreate(
        name="LLM preflight fixture",
        path=str(tmp_path),
    )))

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(server.create_audit_task(
            server.AuditTaskCreate(project_id=project.id, use_llm=True),
            BackgroundTasks(),
        ))

    assert exc_info.value.status_code == 422
    assert "active Chat model" in exc_info.value.detail
    assert not server.audit_tasks_db


def test_audit_task_uses_active_model_configuration(monkeypatch, tmp_path):
    created = asyncio.run(server.create_model_config(_model_config()))
    project = asyncio.run(server.create_project(server.ProjectCreate(
        name="Configured LLM fixture",
        path=str(tmp_path),
    )))
    task_id = "configured-llm-task"
    server.audit_tasks_db[task_id] = server.AuditTask(
        id=task_id,
        project_id=project.id,
        status=server.AuditTaskStatus.PENDING,
        created_at=datetime.now(),
    )
    captured = {}

    def fake_execute(project, use_llm, output_format, llm_config=None):
        captured.update({
            "project": project.id,
            "use_llm": use_llm,
            "output_format": output_format,
            "llm_config": llm_config,
        })
        return {"findings": [], "remediation_bundles": []}

    monkeypatch.setattr(server, "_execute_audit", fake_execute)
    runtime_config = server._active_chat_model_config().runtime_options()
    asyncio.run(server.run_audit_task(
        task_id,
        project,
        use_llm=True,
        output_format="json",
        llm_config=runtime_config,
    ))

    assert captured["project"] == project.id
    assert captured["use_llm"] is True
    assert captured["llm_config"]["model_name"] == created.model_name
    assert server.audit_tasks_db[task_id].status == server.AuditTaskStatus.COMPLETED


def test_openai_compatible_factory_applies_model_parameters_without_network():
    service = create_configured_llm_service(
        provider="openai_compatible",
        api_key="unit-test-secret",
        api_base="https://llm.example.test/v1",
        model_name="audit-model",
        temperature=0.4,
        max_tokens=1024,
    )

    assert isinstance(service, ConfiguredLLMService)
    assert service.provider == "openai_compatible"
    assert service.model == "audit-model"
    assert service.temperature == 0.4
    assert service.max_tokens == 1024


def test_model_config_rejects_labeled_or_non_ascii_api_key_before_persistence():
    invalid_key = "deepseek\u5bc6\u94a5sk-example-token"

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(server.create_model_config(_model_config(api_key=invalid_key)))

    assert exc_info.value.status_code == 422
    assert "printable ASCII token" in exc_info.value.detail
    assert not server.model_configs_db


def test_deepseek_service_rejects_non_ascii_api_key_before_http_client_creation():
    with pytest.raises(ValueError, match="printable ASCII token"):
        DeepSeekService(api_key="deepseek\u5bc6\u94a5sk-example-token")


def test_deepseek_defaults_use_the_v4_openai_compatible_endpoint(monkeypatch):
    captured = {}

    class FakeAsyncOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(AsyncOpenAI=FakeAsyncOpenAI))
    service = DeepSeekService(api_key="unit-test-secret")

    assert service.model == DEEPSEEK_DEFAULT_MODEL == "deepseek-v4-flash"
    assert captured["base_url"] == DEEPSEEK_API_BASE_URL == "https://api.deepseek.com"


def test_model_connection_check_returns_a_redaction_safe_success(monkeypatch):
    created = asyncio.run(server.create_model_config(_model_config()))
    monkeypatch.setattr(
        server,
        "create_configured_llm_service",
        lambda **_kwargs: MockLLMService([LLMResponse(content="READY")]),
    )

    result = asyncio.run(server.test_model_config_connection(created.id))

    assert result.status == "connected"
    assert result.config_id == created.id
    assert "api_key" not in result.model_dump()


def test_model_connection_check_maps_provider_authentication_failure(monkeypatch):
    created = asyncio.run(server.create_model_config(_model_config()))

    class AuthFailureService:
        async def chat(self, *_args, **_kwargs):
            error = RuntimeError("provider rejected request")
            error.status_code = 401
            raise error

    monkeypatch.setattr(
        server,
        "create_configured_llm_service",
        lambda **_kwargs: AuthFailureService(),
    )

    result = asyncio.run(server.test_model_config_connection(created.id))

    assert result.status == "authentication_failed"
    assert "API key" in result.message


def test_default_llm_audit_disables_multi_turn_react_loops(monkeypatch, tmp_path):
    from main import run_audit

    (tmp_path / "app.py").write_text("def hello(name):\n    return name\n", encoding="utf-8")
    monkeypatch.setattr(
        "core.llm_service.create_configured_llm_service",
        lambda **_kwargs: MockLLMService(),
    )

    result = asyncio.run(run_audit(
        project_path=str(tmp_path),
        output_format="json",
        use_llm=True,
        llm_config={
            "provider": "openai_compatible",
            "api_key": "unit-test-secret",
            "api_base": "https://llm.example.test/v1",
            "model_name": "audit-model",
            "temperature": 0.2,
            "max_tokens": 1024,
        },
    ))

    assert result["llm_runtime"]["react_audit_enabled"] is False
    assert result["llm_runtime"]["react_verification_enabled"] is False


def test_llm_request_timeout_bounds_stalled_response(monkeypatch):
    async def stalled_request():
        await asyncio.sleep(0.05)

    monkeypatch.setattr(llm_service, "LLM_REQUEST_TIMEOUT_SECONDS", 0.001)
    with pytest.raises(TimeoutError, match="timed out"):
        asyncio.run(llm_service._await_llm_request(stalled_request(), "test-provider"))


def test_state_reload_reclassifies_incomplete_audit_result(tmp_path):
    project = asyncio.run(server.create_project(server.ProjectCreate(
        name="Partial audit fixture",
        path=str(tmp_path),
    )))
    task = server.AuditTask(
        id="partial-audit-task",
        project_id=project.id,
        status=server.AuditTaskStatus.COMPLETED,
        created_at=datetime.now(),
        completed_at=datetime.now(),
        result={"partial_results": {"phase": "recon"}},
    )
    server.audit_tasks_db[task.id] = task
    server.api_state_store.save_audit_task(task)

    server.configure_state_store(server.api_state_store.path)

    restored = server.audit_tasks_db[task.id]
    assert restored.status == server.AuditTaskStatus.FAILED
    assert "partial results" in restored.error


def test_llm_deep_analysis_honors_payload_candidate_limit(tmp_path):
    responses = [
        LLMResponse(content=(
            '{"is_real_vulnerability": true, "severity": "high", '
            '"confidence": 0.9, "explanation": "Reachable sink.", '
            '"fix_suggestion": "Validate input."}'
        ))
        for _ in range(2)
    ]
    llm = MockLLMService(responses=responses)
    agent = AuditAgent(
        config=AgentConfig(name="audit-test", agent_type=AgentType.AUDIT),
        llm_service=llm,
    )
    for index in range(3):
        filename = f"candidate_{index}.py"
        (tmp_path / filename).write_text("value = request.args.get('value')\n", encoding="utf-8")
        agent.audit_state.candidates.append(CandidateCase(
            id=f"candidate-{index}",
            vulnerability_type="xss",
            severity=Severity.HIGH,
            file_path=filename,
            line_start=1,
            line_end=1,
            description="Input reaches a browser sink.",
            confidence=0.9,
        ))

    asyncio.run(agent._llm_deep_analysis(str(tmp_path), {"llm_deep_analysis_limit": 2}))

    assert llm.call_count == 2
