"""CLI 审计 JSON 瘦身与 retest 回读的契约测试。

真实仓库的全量 JSON 报告可达数百 MB（mem0 实测 418MB），默认输出改为
紧凑报告 + full_result_ref（完整结果归档在 ArtifactStore）；retest 输入
兼容完整结果 / 瘦身报告 / 裸包列表三种形态。
"""

import json
import pathlib
from types import SimpleNamespace

from main import _extract_retest_packages, _persist_full_audit_result, _slim_audit_payload


def _fake_artifact(path):
    return SimpleNamespace(artifact_id="art-1", path=str(path), sha256="ab" * 32, size_bytes=42)


def test_slim_payload_keeps_summary_and_drops_inline_bundles(tmp_path):
    result = {
        "summary": "3 findings",
        "verification_summary": {"total_candidates": 1},
        "merged_findings": [
            {
                "id": "f1", "vulnerability_type": "sql_injection", "severity": "high",
                "file_path": "app.py", "line_start": 10, "line_end": 12,
                "description": "d", "verification_status": "needs_evidence",
                "confidence": 0.6, "evidence_bundle": {"items": ["x" * 100000]},
            }
        ],
        "remediation_bundles": [{"package_id": "p1", "plan": "x" * 100000}],
        "session": {"session_id": "run-1"},
    }
    slim = _slim_audit_payload(result, _fake_artifact(tmp_path / "full.json"))
    assert slim["contract_version"] == "vibe-sec.audit-report.v1"
    assert slim["finding_count"] == 1
    assert slim["findings"][0]["vulnerability_type"] == "sql_injection"
    assert "evidence_bundle" not in slim["findings"][0]
    assert "remediation_bundles" not in slim
    assert slim["remediation_package_ids"] == ["p1"]
    assert slim["full_result_ref"]["sha256"]


def test_extract_retest_packages_supports_three_shapes(tmp_path):
    bundle = [{"package_id": "p1", "state": "completed"}]
    # 完整审计结果
    assert _extract_retest_packages({"remediation_bundles": bundle}) == bundle
    # 裸列表
    assert _extract_retest_packages(bundle) == bundle
    # 瘦身报告 → 经 full_result_ref 回读
    full_path = tmp_path / "full.json"
    full_path.write_text(json.dumps({"remediation_bundles": bundle}), encoding="utf-8")
    slim = {"full_result_ref": {"path": str(full_path), "sha256": "x"}}
    assert _extract_retest_packages(slim) == bundle
    # 瘦身但 ref 失效 → 空列表（不抛异常）
    assert _extract_retest_packages({"full_result_ref": {"path": str(tmp_path / "nope.json")}}) == []


def test_persist_and_roundtrip_on_fixture_project(tmp_path):
    """端到端：fixtures 审计 → 瘦身载荷 → retest 提取能回读全部整改包。"""
    import asyncio
    from main import run_audit

    fixtures = pathlib.Path(__file__).parent / "fixtures"
    result = asyncio.run(
        run_audit(str(fixtures), output_format="json", session_dir=str(tmp_path / "sessions"))
    )
    artifact = _persist_full_audit_result({**result, "session": result.get("session") or {}})
    slim = _slim_audit_payload(result, artifact)
    assert slim["finding_count"] == len(result["merged_findings"])
    assert len(slim["remediation_package_ids"]) == len(result.get("remediation_bundles", []))
    packages = _extract_retest_packages(slim)
    assert packages and len(packages) == len(result.get("remediation_bundles", []))
    slim_text = json.dumps(slim, ensure_ascii=False, default=str)
    assert len(slim_text) < 200000, "fixtures 项目的瘦身报告应远小于全量输出"
