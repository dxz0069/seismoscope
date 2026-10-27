"""retest 闭环 happy path：真实修复 + 证据 + 签名审批 → closure 必须 CLOSED。

对抗性评测（2026-10-26，T3 可用性）曾记录：完成真实修复、构造控制
证据、签名审批后 closure 仍 OPEN——闭环门"防敷衍修复"与"不可用"
一体两面。本文件锁定 happy path：一个真实漏洞从审计 → 修复 → 证
据绑定 → 审批 → retest → closure=closed 的最短完整链路，任何一环
退化（包丢失 retest_plan、证据谓词不匹配、审批未签）都会在此暴露。
"""

from __future__ import annotations

import asyncio
import json

from main import run_audit, run_retest

VULN_APP = (
    'from flask import request\n'
    '\n'
    '\n'
    'def lookup():\n'
    '    query = "SELECT * FROM users WHERE name = \'" + request.args.get("name") + "\'"\n'
    '    return query\n'
)

FIXED_APP = (
    'from flask import request\n'
    '\n'
    '\n'
    'def lookup():\n'
    '    name = request.args.get("name", "")\n'
    '    query = "SELECT * FROM users WHERE name = ?", (name,)\n'
    '    return query\n'
)


def _find_package(result: dict, vuln_type: str = "sql_injection") -> dict:
    for bundle in result.get("remediation_bundles", []) or []:
        if str(bundle.get("vulnerability_type")) == vuln_type:
            return dict(bundle)
    raise AssertionError(f"no remediation bundle for {vuln_type}: "
                         f"{[b.get('vulnerability_type') for b in result.get('remediation_bundles', [])]}")


def _completed_package(package: dict) -> dict:
    """模拟 coding agent 完成修复并按 retest_plan 逐控制项回贴证据。

    证据必须：control_id 对应 plan 步骤、predicate 逐字匹配、
    status=passed、且带 provenance（artifact_ref 等）。
    """
    package = dict(package)
    evidence = []
    for step in package.get("retest_plan", []) or []:
        control_id = str(step.get("control_id", ""))
        if control_id not in {"negative-exploit", "positive-behavior"}:
            continue
        evidence.append({
            "control_id": control_id,
            "predicate": str(step.get("predicate") or step.get("expected_result") or ""),
            "status": "passed",
            "artifact_ref": f"test-artifact://{control_id}",
        })
    package["state"] = "completed"
    package["fix_result"] = {"status": "fixed", "retest_evidence": evidence}
    return package


def test_retest_closure_happy_path_closes(tmp_path, monkeypatch):
    state_root = tmp_path / "state"
    monkeypatch.setenv("VIBE_SEC_STATE_HOME", str(state_root))
    project = tmp_path / "app"
    project.mkdir()
    (project / "app.py").write_text(VULN_APP, encoding="utf-8")
    session_dir = tmp_path / "sessions"

    result = asyncio.run(run_audit(
        project_path=str(project), use_llm=False, session_dir=str(session_dir),
        persist_vrtm=True,
    ))
    package = _find_package(result)
    session_id = str((result.get("session") or {}).get("session_id") or "")
    assert session_id, "审计结果必须携带 session_id（闭环门要求 RunSession）"
    assert [step.get("control_id") for step in package.get("retest_plan", [])][:2] == [
        "negative-exploit", "positive-behavior",
    ], "remediation 包必须预绑定正负控制项，否则修复者无从构造证据"

    # 真实修复落地 + 包按控制项回贴证据
    (project / "app.py").write_text(FIXED_APP, encoding="utf-8")
    completed = _completed_package(package)

    # 高影响变更需要本地签名审批；低影响也一并签发，链路按最严格走
    from core.remediation import issue_remediation_approval

    approval = issue_remediation_approval(
        str(project), session_id=session_id, package_id=str(package["package_id"]),
        reason="happy-path closure regression test", state_root=str(state_root),
    )

    retest = asyncio.run(run_retest(
        str(project), [completed],
        session_dir=str(session_dir), session_id=session_id,
        approval_paths=[str(approval["path"])],
    ))

    closure = retest.get("closure") or {}
    assert closure, f"retest 结果缺少 closure: {sorted(retest.keys())}"
    packages = closure.get("packages") or []
    assert packages, "closure 缺少包级记录"
    record = packages[0]
    assert record.get("blockers") == [], f"happy path 不得有闭环阻断: {record.get('blockers')}"
    assert str(record.get("status")) == "closed", \
        f"真实修复+证据+审批后 closure={record.get('status')}: {json.dumps(record, ensure_ascii=False, default=str)[:400]}"
    assert closure.get("closed_count") == 1 and closure.get("open_count") == 0
