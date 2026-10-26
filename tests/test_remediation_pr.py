"""自动修复 PR 执行器的组装逻辑与 CLI 冒烟。"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "open_remediation_pr.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("open_remediation_pr", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _sample_bundle(**overrides) -> dict:
    bundle = {
        "package_id": "REMEDIATION-cluster-x1",
        "finding_id": "cluster-x1",
        "finding_title": "可能的 SQL 注入",
        "vulnerability_type": "sql_injection",
        "severity": "high",
        "file_path": "api_views/books.py",
        "line_start": 6,
        "line_end": 6,
        "ai_patch_prompt": "Fix security finding cluster-x1.\nLocation: api_views/books.py:6-6.",
        "patch_strategy": "parameterized_query",
        "patch_constraints": [
            {"type": "preserve_behavior", "description": "保留合法行为", "required": True},
            {"type": "least_privilege", "description": "不得扩大权限", "required": False},
        ],
        "change_scope": {"allowed_files": ["api_views/books.py"], "allowed_globs": ["tests/**"]},
        "acceptance_criteria": ["注入负载只被当作参数值", "合法查询仍返回授权结果集"],
        "retest_plan": [
            {"step_number": 1, "description": "重放注入负载", "action": "test_exploit", "expected_result": "查询计划不变"},
        ],
        "verification_status": "needs_evidence",
    }
    bundle.update(overrides)
    return bundle


def test_compose_single_pr_contains_full_instruction_chain():
    module = _load_module()
    entries = module.compose_pr([_sample_bundle()])
    assert len(entries) == 1
    entry = entries[0]
    assert entry["title"].startswith("[seismoscope]") and "×1" in entry["title"]
    body = entry["body"]
    # 修复指令、约束、验收、复测、变更范围、CWE 直链全部入正文
    assert "Fix security finding cluster-x1" in body
    assert "**[必须]** 保留合法行为" in body and "**[建议]** 不得扩大权限" in body
    assert "`tests/**`" in body
    assert "- [ ] 注入负载只被当作参数值" in body
    assert "重放注入负载" in body
    assert "https://cwe.mitre.org/data/definitions/89.html" in body


def test_compose_split_mode_one_pr_per_bundle():
    module = _load_module()
    entries = module.compose_pr(
        [_sample_bundle(), _sample_bundle(package_id="REMEDIATION-cluster-x2", vulnerability_type="api_key",
                                          finding_title="硬编码密钥", file_path="config.py")],
        split=True,
    )
    assert len(entries) == 2
    assert entries[0]["file_name"] != entries[1]["file_name"]
    assert "books.py" in entries[0]["title"] and "config.py" in entries[1]["title"]


def test_bundles_from_filters_invalid_entries():
    module = _load_module()
    result = {"remediation_bundles": [{"package_id": "b1"}, _sample_bundle(), "junk"]}
    bundles = module.bundles_from(result)
    assert len(bundles) == 1


def test_cli_dry_run_outputs_pr_without_side_effects(tmp_path, capsys):
    results = tmp_path / "results.json"
    results.write_text(json.dumps({"remediation_bundles": [_sample_bundle()]}, ensure_ascii=False), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(results), "--dry-run"],
        capture_output=True, text=True, encoding="utf-8", timeout=120, cwd=str(ROOT),
    )
    assert completed.returncode == 0, completed.stderr
    assert "PR 标题: [seismoscope]" in completed.stdout
    assert "dry-run" in completed.stdout
    assert "未执行任何操作" in completed.stdout


def test_cli_no_bundles_exits_with_error(tmp_path):
    results = tmp_path / "results.json"
    results.write_text(json.dumps({"remediation_bundles": []}, ensure_ascii=False), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(results), "--dry-run"],
        capture_output=True, text=True, encoding="utf-8", timeout=120, cwd=str(ROOT),
    )
    assert completed.returncode == 2
    assert "没有 RemediationBundle" in completed.stderr
