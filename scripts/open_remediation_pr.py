"""自动修复 PR 执行器：把 RemediationBundle 送进 GitHub Pull Request。

定位（Pixee 模式的候风变体）：审计产出的是"修复指令包"而非机械补丁——
本脚本把每个 Bundle 组装成一份 AI 编码助手可直接消费的 PR（正文即
ai_patch_prompt + 约束 + 验收条件 + 复测计划，附件文件落在
.seismoscope/remediation/），使修复工作进入标准 GitHub 协作流。

用法::

    # 先产出审计 JSON
    vibe-sec audit . --format json -o results.json
    # 预览（无副作用）
    python scripts/open_remediation_pr.py results.json --dry-run
    # 在当前 git 仓库创建分支并开 PR（需要 gh CLI 已登录）
    python scripts/open_remediation_pr.py results.json --repo dxz0069/my-app
    # 每个漏洞单独一个 PR
    python scripts/open_remediation_pr.py results.json --split

原理：分支上提交 .seismoscope/remediation/<package_id>.md（PR 的实体文件），
PR 标题带 [seismoscope] 前缀与严重级；正文由 compose 函数纯函数生成，
可离线测试。
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.audit.standards_map import standards_for  # noqa: E402


def bundles_from(result: dict[str, Any]) -> list[dict[str, Any]]:
    bundles = result.get("remediation_bundles") or []
    return [b for b in bundles if isinstance(b, dict) and b.get("ai_patch_prompt")]


def _severity_badge(severity: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(
        str(severity).lower(), "⚪"
    )


def _standards_line(vulnerability_type: str) -> str:
    standards = standards_for(vulnerability_type)
    if not standards:
        return ""
    if standards["id"]:
        return f"**标准**: [{standards['id']}]({standards['help_uri']})\n\n"
    tags = "、".join(f"`{tag}`" for tag in standards["tags"])
    return f"**标准**: {tags}（[OWASP]({standards['help_uri']})）\n\n"


def compose_bundle_section(bundle: dict[str, Any]) -> str:
    """单个 Bundle 的 PR 正文段落。"""
    lines: list[str] = []
    title = bundle.get("finding_title") or bundle.get("title") or bundle.get("vulnerability_type", "finding")
    lines.append(f"## {_severity_badge(bundle.get('severity'))} {title}")
    lines.append("")
    location = f"`{bundle.get('file_path', '?')}`:{bundle.get('line_start', '?')}-{bundle.get('line_end', '?')}"
    lines.append(f"**位置**: {location} | **类型**: `{bundle.get('vulnerability_type', 'unknown')}`"
                 f" | **策略**: `{bundle.get('patch_strategy', '-')}`"
                 f" | **状态**: `{bundle.get('verification_status', '-')}`")
    lines.append("")
    lines.append(_standards_line(str(bundle.get("vulnerability_type", ""))))

    lines.append("### 修复指令（供 AI 编码助手直接执行）")
    lines.append("")
    lines.append("```text")
    lines.append(str(bundle.get("ai_patch_prompt", "")).strip())
    lines.append("```")
    lines.append("")

    constraints = bundle.get("patch_constraints") or []
    if constraints:
        lines.append("### 修改约束")
        lines.append("")
        for item in constraints:
            mark = "必须" if item.get("required") else "建议"
            lines.append(f"- **[{mark}]** {item.get('description', '')}（`{item.get('type', '')}`）")
        lines.append("")

    scope = bundle.get("change_scope") or {}
    allowed = scope.get("allowed_files") or []
    globs = scope.get("allowed_globs") or []
    if allowed or globs:
        lines.append("### 变更范围")
        lines.append("")
        lines.append(f"- 允许文件: {', '.join(f'`{p}`' for p in allowed) or '-'}")
        lines.append(f"- 允许模式: {', '.join(f'`{g}`' for g in globs) or '-'}")
        lines.append("")

    criteria = bundle.get("acceptance_criteria") or []
    if criteria:
        lines.append("### 验收条件")
        lines.append("")
        for item in criteria:
            lines.append(f"- [ ] {item}")
        lines.append("")

    retest = bundle.get("retest_plan") or []
    if retest:
        lines.append("### 复测计划")
        lines.append("")
        for step in retest:
            lines.append(f"{step.get('step_number', '·')}. {step.get('description', '')}"
                         f" — *{step.get('action', '')}* → {step.get('expected_result', '')}")
        lines.append("")
    return "\n".join(lines)


def compose_pr(bundles: list[dict[str, Any]], *, split: bool = False) -> list[dict[str, str]]:
    """组装 PR 列表：split=False 汇总单 PR，split=True 每个漏洞一个 PR。"""
    if not bundles:
        return []
    if split:
        entries = []
        for bundle in bundles:
            title = bundle.get("finding_title") or bundle.get("vulnerability_type", "finding")
            entries.append({
                "title": f"[seismoscope] 修复 {_severity_badge(bundle.get('severity'))} {title}"
                         f"（{bundle.get('file_path', '?')}:{bundle.get('line_start', '?')}）",
                "body": compose_bundle_section(bundle),
                "file_name": f"{bundle.get('package_id', 'bundle')}.md",
            })
        return entries
    section_text = "\n---\n\n".join(compose_bundle_section(b) for b in bundles)
    highest = max(
        (str(b.get("severity", "low")) for b in bundles),
        key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0),
    )
    body = (
        f"候风 Seismoscope 审计产出 {len(bundles)} 个修复指令包。"
        "每个包包含精确到文件行号的修复指令、修改约束、验收条件与复测计划——"
        "请让 AI 编码助手按包执行，完成后逐项勾选验收条件。\n\n"
        f"{section_text}\n\n---\n\n*由 `scripts/open_remediation_pr.py` 生成；"
        "复测通过后合并。*"
    )
    return [{
        "title": f"[seismoscope] 安全修复指令 ×{len(bundles)}（最高严重级 {highest}）",
        "body": body,
        "file_name": "remediation.md",
    }]


def _run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", check=check)


def create_pull_requests(entries: list[dict[str, str]], *, repo: str, base: str, branch_prefix: str) -> None:
    if shutil.which("gh") is None:
        print("错误：未找到 gh CLI，请安装并登录（gh auth login）。", file=sys.stderr)
        sys.exit(2)
    for index, entry in enumerate(entries, 1):
        branch = f"{branch_prefix}-{index}"
        target = Path(".seismoscope") / "remediation" / entry["file_name"]
        _run(["git", "checkout", "-b", branch])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(entry["body"], encoding="utf-8", newline="\n")
        _run(["git", "add", str(target)])
        _run(["git", "commit", "-m", f"seismoscope: add remediation package {entry['file_name']}"])
        _run(["git", "push", "-u", "origin", branch])
        completed = _run([
            "gh", "pr", "create", "--repo", repo, "--base", base,
            "--head", branch, "--title", entry["title"], "--body-file", "-",
        ], check=False)
        if completed.returncode == 0:
            print(f"PR 已创建: {completed.stdout.strip()}")
        else:
            print(f"PR 创建失败（分支 {branch} 已推送，可手动创建）: {completed.stderr.strip()}", file=sys.stderr)
        _run(["git", "checkout", "-"])


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="把审计 JSON 中的 RemediationBundle 转成 GitHub PR")
    parser.add_argument("results", help="vibe-sec audit --format json -o 的输出文件")
    parser.add_argument("--repo", help="目标仓库 owner/name（默认取当前 git remote）")
    parser.add_argument("--base", default="main", help="PR 目标分支（默认 main）")
    parser.add_argument("--branch-prefix", default="seismoscope/remediation", help="分支名前缀")
    parser.add_argument("--split", action="store_true", help="每个漏洞单独一个 PR（默认汇总单 PR）")
    parser.add_argument("--dry-run", action="store_true", help="仅打印 PR 标题与正文，不执行 git/gh 操作")
    args = parser.parse_args()

    result = json.loads(Path(args.results).read_text(encoding="utf-8"))
    bundles = bundles_from(result)
    if not bundles:
        print("审计结果中没有 RemediationBundle（无 findings 或未生成整改包）。", file=sys.stderr)
        return 2

    entries = compose_pr(bundles, split=args.split)
    if args.dry_run:
        for entry in entries:
            print("=" * 72)
            print(f"PR 标题: {entry['title']}")
            print(f"附件文件: .seismoscope/remediation/{entry['file_name']}")
            print("-" * 72)
            print(entry["body"])
        print("=" * 72)
        print(f"共 {len(entries)} 个 PR（dry-run，未执行任何操作）")
        return 0

    repo = args.repo
    if not repo:
        remote = _run(["git", "config", "--get", "remote.origin.url"], check=False).stdout.strip()
        if "github.com" not in remote:
            print("错误：无法从 remote.origin.url 推断仓库，请用 --repo owner/name 指定。", file=sys.stderr)
            return 2
        tail = remote.split("github.com")[-1].lstrip(":/").removesuffix(".git")
        repo = tail
    create_pull_requests(entries, repo=repo, base=args.base, branch_prefix=args.branch_prefix)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
