"""Finding 级抑制：本地抑制库 + 合并阶段过滤的契约测试。

抑制只认工具侧本地存储（VIBE_SEC_STATE_HOME 下的 suppressions 目录），
被审计源码内的任何指令不影响检出（对抗评测已验证的完整性边界）。
"""

import asyncio
import pathlib

from core.audit.suppression import (
    add_suppression,
    apply_suppressions,
    load_suppressions,
    match_suppression,
)


def test_suppression_store_roundtrip_and_match(tmp_path, monkeypatch):
    monkeypatch.setenv("VIBE_SEC_STATE_HOME", str(tmp_path))
    project = tmp_path / "proj"
    project.mkdir()
    entry = add_suppression(
        str(project), vulnerability_type="sql_injection", file_path="app.py", line=10, reason="fixture"
    )
    assert load_suppressions(str(project))[0]["id"] == entry["id"]
    hit = {"vulnerability_type": "sql_injection", "file_path": "app.py", "line_start": 12}
    miss_type = {"vulnerability_type": "xss", "file_path": "app.py", "line_start": 12}
    miss_line = {"vulnerability_type": "sql_injection", "file_path": "app.py", "line_start": 40}
    assert match_suppression(hit, load_suppressions(str(project))) is not None
    assert match_suppression(miss_type, load_suppressions(str(project))) is None
    assert match_suppression(miss_line, load_suppressions(str(project))) is None


def test_suppression_survives_absolute_path_shapes(tmp_path, monkeypatch):
    monkeypatch.setenv("VIBE_SEC_STATE_HOME", str(tmp_path))
    project = tmp_path / "proj"
    project.mkdir()
    add_suppression(
        str(project), vulnerability_type="prompt_injection",
        file_path="web\\templates\\x.py", reason="noise",
    )
    finding = {"vulnerability_type": "prompt_injection", "file_path": r"web\templates\x.py", "line_start": 1}
    assert match_suppression(finding, load_suppressions(str(project))) is not None


def test_apply_suppressions_filters_and_reports(tmp_path, monkeypatch):
    monkeypatch.setenv("VIBE_SEC_STATE_HOME", str(tmp_path))
    project = tmp_path / "proj"
    project.mkdir()
    add_suppression(str(project), vulnerability_type="sql_injection", file_path="app.py", reason="dup")
    findings = [
        {"vulnerability_type": "sql_injection", "file_path": "app.py", "line_start": 10},
        {"vulnerability_type": "xss", "file_path": "app.py", "line_start": 10},
    ]
    kept, suppressed = apply_suppressions(findings, str(project))
    assert [f["vulnerability_type"] for f in kept] == ["xss"]
    assert len(suppressed) == 1 and suppressed[0]["suppression"]["reason"] == "dup"


def test_end_to_end_audit_applies_suppression(tmp_path, monkeypatch):
    monkeypatch.setenv("VIBE_SEC_STATE_HOME", str(tmp_path))
    from main import run_audit

    fixtures = pathlib.Path(__file__).parent / "fixtures"
    add_suppression(
        str(fixtures), vulnerability_type="sql_injection", file_path="vulnerable_app.py", reason="test suppress"
    )
    result = asyncio.run(
        run_audit(str(fixtures), output_format="json", session_dir=str(tmp_path / "sessions"))
    )
    types_in_file = [
        f.get("vulnerability_type")
        for f in result["merged_findings"]
        if str(f.get("file_path", "")).endswith("vulnerable_app.py")
    ]
    assert "sql_injection" not in types_in_file
    assert any(
        str(s.get("finding", {}).get("file_path", "")).endswith("vulnerable_app.py")
        for s in result.get("suppressed_findings", [])
    )
