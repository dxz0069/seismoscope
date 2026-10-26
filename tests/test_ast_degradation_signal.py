"""run_audit 必须把 AST 泳道降级显式化：预检提示 + 结果契约回填。

背景：解析器下载失败（离线/受限网络首跑最常见）时各泳道静默降级为
正则分析，消费者无法分辨全精度与降级结果。这里锁定两条信号链路。
"""

from __future__ import annotations

import asyncio
import logging

from core.languages import tree_sitter_gateway as gateway
from main import run_audit


def _ready_status():
    return {
        "contract_version": "vibe-sec.tree-sitter-status.v1",
        "pack_installed": True, "enabled": True, "cache_dir": "/cache",
        "languages": {name: True for name in gateway.DEFAULT_LANGUAGES},
        "all_ready": True, "hint": "默认语言解析器已就绪",
    }


def _blocked_status():
    return {
        "contract_version": "vibe-sec.tree-sitter-status.v1",
        "pack_installed": True, "enabled": True, "cache_dir": None,
        "languages": {name: False for name in gateway.DEFAULT_LANGUAGES},
        "all_ready": False,
        "hint": "解析器未缓存：在线环境 vibe-sec setup 预热，离线设置 VIBE_SEC_TREE_SITTER_CACHE 或 VIBE_SEC_DISABLE_TREE_SITTER=1",
    }


def _tiny_project(tmp_path):
    (tmp_path / "app.py").write_text(
        'import os\n'
        '\n'
        'def handler(request):\n'
        '    query = "SELECT * FROM t WHERE id = " + request.args.get("id")\n'
        '    return query\n',
        encoding="utf-8",
    )
    return tmp_path


def test_audit_result_carries_ast_degradation_when_parsers_failed(tmp_path, monkeypatch):
    monkeypatch.setattr(gateway, "status", _ready_status)
    monkeypatch.setattr(gateway, "degraded_languages", lambda: ["python"])

    result = asyncio.run(run_audit(project_path=str(_tiny_project(tmp_path)), use_llm=False))

    degradation = result.get("ast_degradation")
    assert degradation is not None, "解析器失败语言必须回填结果契约"
    assert degradation["languages"] == ["python"]
    assert "正则" in degradation["impact"]
    assert "VIBE_SEC_TREE_SITTER_CACHE" in degradation["hint"]
    assert "VIBE_SEC_DISABLE_TREE_SITTER" in degradation["hint"]


def test_audit_logs_preflight_hint_when_ast_not_ready(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(gateway, "status", _blocked_status)
    monkeypatch.setattr(gateway, "degraded_languages", lambda: [])

    with caplog.at_level(logging.INFO, logger="main"):
        asyncio.run(run_audit(project_path=str(_tiny_project(tmp_path)), use_llm=False))

    preflight = [record for record in caplog.records if "AST lane not ready" in record.message]
    assert preflight, "首跑未就绪必须输出双分支指引日志"
    assert "vibe-sec setup" in preflight[0].message
    assert "VIBE_SEC_TREE_SITTER_CACHE" in preflight[0].message


def test_clean_audit_has_no_degradation_key_and_no_noise(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(gateway, "status", _ready_status)
    monkeypatch.setattr(gateway, "degraded_languages", lambda: [])

    with caplog.at_level(logging.INFO, logger="main"):
        result = asyncio.run(run_audit(project_path=str(_tiny_project(tmp_path)), use_llm=False))

    assert "ast_degradation" not in result
    assert not [record for record in caplog.records if "AST lane not ready" in record.message]


def test_degraded_warning_logged_after_audit(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(gateway, "status", _ready_status)
    monkeypatch.setattr(gateway, "degraded_languages", lambda: ["typescript"])

    with caplog.at_level(logging.WARNING, logger="main"):
        asyncio.run(run_audit(project_path=str(_tiny_project(tmp_path)), use_llm=False))

    assert [record for record in caplog.records if "AST lane degraded" in record.message]
