"""外置规则加载器：默认同步、损坏回落、自定义扩展。"""

from __future__ import annotations

import yaml

from agents.audit_agent import AuditAgent
from core.audit.rules_registry import ENV_RULES_PATH, as_agent_rule_map, load_pattern_rules


def _builtin_groups(agent=None):
    agent = agent or AuditAgent()
    return {
        "web_vulnerability_patterns": agent.web_vulnerability_patterns,
        "agent_vulnerability_patterns": agent.agent_vulnerability_patterns,
        "workflow_vulnerability_patterns": agent.workflow_vulnerability_patterns,
        "secret_patterns": agent.secret_patterns,
    }


def test_default_yaml_stays_in_sync_with_builtin_golden():
    """默认规则文件与内置字典必须逐条一致——CI 强制双源同步。"""
    loaded = load_pattern_rules(path=None)
    import os

    assert os.environ.get(ENV_RULES_PATH) is None, "本用例要求未设置自定义规则环境变量"
    assert loaded is not None
    builtin = _builtin_groups()
    for group, rules in loaded.items():
        rule_map = as_agent_rule_map(rules)
        reference = builtin[group]
        assert set(rule_map) == set(reference), f"{group} 规则类型集合漂移"
        for vuln_type, rule in rule_map.items():
            assert rule["patterns"] == reference[vuln_type]["patterns"], f"{group}/{vuln_type} 模式漂移"
            assert rule["severity"] == reference[vuln_type]["severity"], f"{group}/{vuln_type} 严重级漂移"


def test_missing_file_falls_back(monkeypatch, tmp_path):
    assert load_pattern_rules(path=str(tmp_path / "nope.yml")) is None


def test_malformed_file_falls_back(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text(":\n  - [unbalanced", encoding="utf-8")
    assert load_pattern_rules(path=str(bad)) is None


def test_invalid_entries_skipped_and_empty_falls_back(tmp_path):
    doc = {"web_vulnerability_patterns": [
        {"vulnerability_type": "", "severity": "high", "patterns": ["x"]},          # type 空
        {"vulnerability_type": "ok_type", "severity": "ultra", "patterns": ["x"]},  # severity 非法
        {"vulnerability_type": "no_patterns", "severity": "high", "patterns": []},  # 模式空
    ]}
    empty = tmp_path / "empty.yml"
    empty.write_text(yaml.safe_dump(doc), encoding="utf-8")
    assert load_pattern_rules(path=str(empty)) is None  # 无有效条目 -> 整体回落


def test_custom_rules_extend_detection(tmp_path, monkeypatch):
    """社区自定义规则：新类型经环境变量生效并可检出。"""
    base = load_pattern_rules(path=None)
    rules = {
        "web_vulnerability_patterns": list(base["web_vulnerability_patterns"]) + [{
            "vulnerability_type": "custom_marker_rule",
            "severity": "high",
            "description": "自定义规则测试",
            "patterns": [r"CUSTOM_INSECURE_MARKER_[A-Z]+"],
        }],
    }
    custom = tmp_path / "custom.yml"
    custom.write_text(yaml.safe_dump(rules, allow_unicode=True), encoding="utf-8")
    monkeypatch.setenv(ENV_RULES_PATH, str(custom))

    agent = AuditAgent()
    assert "custom_marker_rule" in agent.web_vulnerability_patterns
    # 内置规则不被自定义文件裁剪其余组：secrets 等组回落内置
    assert agent.secret_patterns == _builtin_groups()["secret_patterns"]

    import asyncio, tempfile
    from pathlib import Path as P
    from main import run_audit

    with tempfile.TemporaryDirectory() as td:
        (P(td) / "x.py").write_text(
            "value = 'CUSTOM_INSECURE_MARKER_HERE'\n", encoding="utf-8")
        result = asyncio.run(run_audit(str(td), use_llm=False, output_format="json"))
        data = result if isinstance(result, dict) else __import__("json").loads(result)
        types = {f.get("vulnerability_type") for f in data.get("findings", [])}
        assert "custom_marker_rule" in types
