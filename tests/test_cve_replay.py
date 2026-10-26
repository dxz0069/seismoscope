"""CVE 回放回归：以外部真值（GHSA/CVE 修复 commit 的父提交快照）为基线。

vendored 目标来自真实开源仓库的漏洞版本快照（许可见各目录内 LICENSE），
行级命中标准：expected_types 中的漏洞类型出现在修复文件 diff hunk ±8 行内。

当前基线 0/3，全部 strict xfail——检测器补上某类召回后对应用例翻成
XPASS 并使 CI 失败，强制维护者移除该目标的 xfail 标记并更新基线计数；
召回倒退同样直接可见。完整 11 目标回放与评测数据见对抗性评测报告。
"""

import asyncio
import json
import pathlib
import shutil

import pytest

from main import run_audit

FIXTURES = pathlib.Path(__file__).parent / "regression_fixtures" / "cve_replay"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
XFAIL_REASON = "CVE 行级召回基线 0/3：检测器升级后移除对应目标的 xfail 标记"


def _params():
    return [
        pytest.param(
            target,
            id=f"{target['target']}[{target['cwe']}]",
            marks=pytest.mark.xfail(strict=True, reason=XFAIL_REASON),
        )
        for target in MANIFEST["targets"]
    ]


def _line_hits(findings, target):
    hits = []
    for fix in target["fix_files"]:
        for finding in findings:
            path = str(finding.get("file_path", "")).replace("\\", "/")
            if not path.endswith(fix["file"]):
                continue
            if finding.get("vulnerability_type") not in target["expected_types"]:
                continue
            line = int(finding.get("line_start", 0))
            if any(abs(line - hunk) <= 8 for hunk in fix["hunk_lines"]):
                hits.append(finding)
    return hits


@pytest.mark.parametrize("target", _params())
def test_cve_replay_line_level_recall(tmp_path, target):
    project = tmp_path / target["target"]
    shutil.copytree(FIXTURES / target["target"], project)
    result = asyncio.run(
        run_audit(str(project), output_format="json", session_dir=str(tmp_path / "sessions"))
    )
    findings = result.get("merged_findings", [])
    hits = _line_hits(findings, target)
    assert hits, (
        f"{target['target']}: 未在 {target['cwe']} 修复行 ±8 内检出 "
        f"{target['expected_types']}（总 finding={len(findings)}，"
        f"类型={sorted({f.get('vulnerability_type') for f in findings})}）"
    )
