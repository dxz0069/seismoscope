"""CLI LLM 提供方参数：--llm-provider/--llm-model/--llm-api-base。

审计报告（2026-10-26）指出：库层（run_audit → create_configured_
llm_service）早已支持 openai/openai_compatible/anthropic/auto 多提
供方，CLI 却只有 DeepSeek 环境变量一条路——用户无从切换提供方。
本文件锁定参数组装、前置校验与 run_audit 透传。
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import main
from main import _cli_llm_config


def _args(**kw):
    base = {"llm_provider": None, "llm_model": None, "llm_api_base": None,
            "api_key": None, "use_llm": False}
    base.update(kw)
    return SimpleNamespace(**base)


class TestCliLlmConfig:
    def test_absent_provider_returns_none_for_legacy_path(self):
        assert _cli_llm_config(_args()) is None

    def test_orphan_model_or_base_without_provider_is_rejected(self):
        with pytest.raises(ValueError, match="--llm-provider"):
            _cli_llm_config(_args(llm_model="gpt-x"))
        with pytest.raises(ValueError, match="--llm-provider"):
            _cli_llm_config(_args(llm_api_base="http://localhost:8000/v1"))

    def test_provider_requires_model(self):
        with pytest.raises(ValueError, match="--llm-model"):
            _cli_llm_config(_args(llm_provider="openai", api_key="k"))

    def test_provider_requires_credentials(self, monkeypatch):
        monkeypatch.delenv("VIBE_SEC_DEEPSEEK_API_KEY", raising=False)
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        with pytest.raises(ValueError, match="凭据"):
            _cli_llm_config(_args(llm_provider="openai", llm_model="gpt-x"))

    def test_compatible_providers_require_api_base(self):
        for provider in ("openai_compatible", "auto"):
            with pytest.raises(ValueError, match="--llm-api-base"):
                _cli_llm_config(_args(llm_provider=provider, llm_model="m", api_key="k"))

    def test_full_config_assembly_prefers_flag_key_over_env(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "env-key")
        config = _cli_llm_config(_args(
            llm_provider="openai_compatible", llm_model="qwen-max",
            llm_api_base="http://localhost:8000/v1", api_key="flag-key",
        ))
        assert config == {
            "provider": "openai_compatible",
            "api_key": "flag-key",
            "model_name": "qwen-max",
            "api_base": "http://localhost:8000/v1",
        }

    def test_env_key_is_accepted_when_flag_absent(self, monkeypatch):
        monkeypatch.setenv("VIBE_SEC_DEEPSEEK_API_KEY", "env-key")
        config = _cli_llm_config(_args(llm_provider="openai", llm_model="gpt-x"))
        assert config["api_key"] == "env-key"


def test_audit_dispatch_passes_llm_config_and_implies_use_llm(tmp_path, monkeypatch, capsys):
    captured = {}

    async def fake_run_audit(project_path, **kwargs):
        captured.update(kwargs)
        return {"findings": [], "orchestration_completed": True}

    monkeypatch.setattr(main, "run_audit", fake_run_audit)
    monkeypatch.setattr(main, "format_result", lambda result, fmt: "report")
    argv = [
        "vibe-sec", "audit", str(tmp_path),
        "--llm-provider", "anthropic", "--llm-model", "claude-x",
        "--api-key", "k", "--format", "markdown",
    ]
    monkeypatch.setattr("sys.argv", argv)
    main.main()

    assert captured["llm_config"] == {
        "provider": "anthropic", "api_key": "k",
        "model_name": "claude-x", "api_base": None,
    }
    assert captured["use_llm"] is True, "--llm-provider 必须隐含启用 LLM 通道"


def test_audit_dispatch_rejects_incomplete_provider_config(tmp_path, monkeypatch, capsys):
    called = {"n": 0}

    async def fake_run_audit(project_path, **kwargs):  # pragma: no cover - 不应被调
        called["n"] += 1
        return {}

    monkeypatch.setattr(main, "run_audit", fake_run_audit)
    monkeypatch.setattr("sys.argv", [
        "vibe-sec", "audit", str(tmp_path),
        "--llm-provider", "openai", "--format", "markdown",
    ])
    with pytest.raises(SystemExit) as excinfo:
        main.main()
    assert excinfo.value.code == 1
    assert called["n"] == 0
    assert "llm-model" in capsys.readouterr().out
