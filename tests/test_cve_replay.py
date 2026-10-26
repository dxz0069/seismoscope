"""CVE 回放回归：以外部真值（GHSA/CVE 修复 commit 的父提交快照）为基线。

vendored 目标来自真实开源仓库的漏洞版本快照（许可见各目录内 LICENSE），
行级命中标准：expected_types 中的漏洞类型出现在修复文件 diff hunk ±8 行内。

当前基线 2/3 已命中（v0.13.0：mistune CWE-22、launch-editor CWE-78）。
serialize-javascript 保持 strict xfail：其漏洞形态是转义正则的语义绕过
（`</script` 出现在序列化函数体末尾时未转义），源码表面看已加固——静态
正则探测器原理性不可见，它是 "false positivity"（看着干净实则可绕过）
的标本，归 LLM 语义审查通道职责。检测器若意外命中会翻 XPASS 并使 CI
失败，强制复核。召回倒退（已命中的 2 目标失败）同样直接可见。
"""

import asyncio
import json
import pathlib
import shutil

import pytest

from main import run_audit

FIXTURES = pathlib.Path(__file__).parent / "regression_fixtures" / "cve_replay"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
# 语义绕过类目标：静态模式原理性不可见，归 LLM 通道（见模块 docstring）。
SEMANTIC_ONLY_TARGETS = {
    "serialize-javascript": "转义正则的语义绕过，静态模式不可见（false positivity 标本）",
}


def _params():
    return [
        pytest.param(
            target,
            id=f"{target['target']}[{target['cwe']}]",
            marks=(
                [pytest.mark.xfail(strict=True, reason=SEMANTIC_ONLY_TARGETS[target["target"]])]
                if target["target"] in SEMANTIC_ONLY_TARGETS
                else []
            ),
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
