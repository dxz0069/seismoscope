"""LLM 语义通道验收：在 CVE 回放靶场上度量 LLM 审计的行级命中。

定位：静态模式原理性不可见的语义绕过（serialize-javascript 的转义
正则绕过，即 "false positivity" 标本）以本脚本验收 LLM 语义通道；
静态可命中的目标（mistune / launch-editor）作为对照组——对照组未
命中说明本次 LLM 运行不可信，整体结论标记 inconclusive。

需要模型凭据（VIBE_SEC_DEEPSEEK_API_KEY / DEEPSEEK_API_KEY 或
--api-key），缺失时退出码 2；模型调用失败的目标标记 error 而不中断。

用法::

    python scripts/cve_replay_llm.py --json llm-baseline.json
    python scripts/cve_replay_llm.py --targets serialize-javascript
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import tempfile
import time
from datetime import UTC
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURES = ROOT / "tests" / "regression_fixtures" / "cve_replay"
MANIFEST_PATH = FIXTURES / "manifest.json"


def load_targets(only: list[str] | None = None) -> list[dict[str, Any]]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    targets = manifest["targets"]
    if only:
        targets = [t for t in targets if t["target"] in set(only)]
    return targets


def line_hits(findings: list[dict[str, Any]], target: dict[str, Any]) -> list[dict[str, Any]]:
    """行级命中：expected_types 出现在修复文件 hunk ±8 行内（与静态回放同标准）。"""
    hits = []
    for fix in target["fix_files"]:
        for finding in findings:
            path = str(finding.get("file_path", "")).replace("\\", "/")
            if not path.endswith(fix["file"]):
                continue
            if finding.get("vulnerability_type") not in target["expected_types"]:
                continue
            line = int(finding.get("line_start", 0) or 0)
            if any(abs(line - hunk) <= 8 for hunk in fix["hunk_lines"]):
                hits.append(finding)
    return hits


# 静态通道已命中的目标：作为 LLM 运行的可信度对照组（见 tests/test_cve_replay.py）。
# v0.16.0 起 serialize-javascript 由 escape_semantics 确定性检出，归入对照组；
# 当前 4 个 vendor 目标全部静态可命中——后续新增语义类目标时移回语义集。
STATIC_CONTROL_TARGETS = {"mistune", "launch-editor", "systeminformation", "serialize-javascript"}


async def run_target(target: dict[str, Any], *, use_llm: bool, api_key: str | None) -> dict[str, Any]:
    from main import run_audit

    started = time.time()
    with tempfile.TemporaryDirectory(prefix="cve-llm-") as td:
        project = Path(td) / target["target"]
        shutil.copytree(FIXTURES / target["target"], project)
        result = await run_audit(
            str(project), use_llm=use_llm, api_key=api_key, output_format="json",
        )
    data = json.loads(result) if isinstance(result, str) else result
    findings = data.get("merged_findings", []) or []
    hits = line_hits(findings, target)
    return {
        "target": target["target"],
        "cwe": target["cwe"],
        "mode": "llm" if use_llm else "static",
        "findings_count": len(findings),
        "hit": bool(hits),
        "hit_findings": [
            {"type": h.get("vulnerability_type"), "file": h.get("file_path"), "line": h.get("line_start")}
            for h in hits
        ],
        "elapsed_s": round(time.time() - started, 1),
    }


def summarize(report: list[dict[str, Any]]) -> dict[str, Any]:
    controls = [r for r in report if r["target"] in STATIC_CONTROL_TARGETS]
    controls_ok = bool(controls) and all(r["hit"] for r in controls)
    semantic = [r for r in report if r["target"] not in STATIC_CONTROL_TARGETS]
    semantic_hits = [r for r in semantic if r["hit"]]
    return {
        "semantic_targets": len(semantic),
        "semantic_hits": len(semantic_hits),
        "controls_passed": controls_ok,
        "conclusion": (
            "no-semantic-targets" if controls_ok and not semantic else
            "accept" if controls_ok and semantic_hits else
            "reject" if controls_ok else
            "inconclusive"
        ),
        "note": (
            "对照组（静态可命中目标）未全部命中，本次 LLM 运行不足以为语义结论背书"
            if not controls_ok else
            "当前无语义类目标，仅对照组运行"
            if not semantic else
            "语义目标命中 = LLM 通道通过验收"
            if semantic_hits else
            "对照组可信但语义目标未命中：LLM 通道未通过本次验收（reject）"
        ),
    }


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="LLM 语义通道 CVE 回放验收")
    parser.add_argument("--targets", action="append", help="只跑指定目标（可多次）")
    parser.add_argument("--api-key", help="DeepSeek API Key（缺省读环境变量）")
    parser.add_argument("--static", action="store_true", help="同时跑静态对照（默认只跑 LLM）")
    parser.add_argument("--json", help="结果写入的 JSON 文件")
    args = parser.parse_args()

    api_key = args.api_key or os.getenv("VIBE_SEC_DEEPSEEK_API_KEY") or os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        print(
            "缺少模型凭据：设置 VIBE_SEC_DEEPSEEK_API_KEY / DEEPSEEK_API_KEY 或传 --api-key。",
            file=sys.stderr,
        )
        return 2

    targets = load_targets(args.targets)
    if not targets:
        print("没有匹配的目标。", file=sys.stderr)
        return 2

    report: list[dict[str, Any]] = []
    for target in targets:
        print(f"[llm] {target['target']}（{target['cwe']}）运行中…", flush=True)
        try:
            entry = asyncio.run(run_target(target, use_llm=True, api_key=api_key))
        except Exception as exc:  # 模型/网络故障标记 error，不中断其余目标
            entry = {
                "target": target["target"], "cwe": target["cwe"], "mode": "llm",
                "error": f"{type(exc).__name__}: {exc}", "hit": False,
            }
        report.append(entry)
        print(f"  -> hit={entry['hit']} findings={entry.get('findings_count')} {entry.get('elapsed_s', '')}s")

    if args.static:
        for target in targets:
            entry = asyncio.run(run_target(target, use_llm=False, api_key=None))
            entry["target"] = entry["target"] + " [static]"
            report.append(entry)

    from datetime import datetime

    document = {
        "contract_version": "seismoscope.cve-replay-llm.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "results": report,
        "summary": summarize([r for r in report if r.get("mode") == "llm"]),
    }
    print(json.dumps(document["summary"], ensure_ascii=False, indent=2))
    if args.json:
        Path(args.json).write_text(
            json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"结果已写入 {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
