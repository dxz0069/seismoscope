"""靶场召回/误报基准：确定性（无 LLM）审计能力基线，防止能力回退。

用法::

    python scripts/benchmark_recall.py                     # 运行内置靶场集
    python scripts/benchmark_recall.py --json out.json     # 保存结果
    python scripts/benchmark_recall.py --compare base.json # 对比基线，回退则退出码 1
    python scripts/benchmark_recall.py --project /path/to/VAmPI --label vampi \\
        --expect sql_injection,api_key                     # 外部靶场（如真实 VAmPI / Juice Shop）

内置靶场集（与 tests/test_web_audit_recall.py 同源）：

- ``web-fixture``    Flask 漏洞样例（7 类植入漏洞）
- ``agent-fixture``  智能体漏洞样例（提示词注入 / MCP / 过度代理 / 密钥 / SQL）
- ``vampi-mini``     VAmPI 风格迷你靶场（SQL 两种形态 / 特权自赋值 / 明文密码比较 / 弱密钥）
- ``safe-app``       安全写法样例（期望零检出，衡量误报）

判定规则：

- 召回按"漏洞类型集合"计算：某类型在该靶场集下至少命中一条 finding 即算命中；
- safe-app 中的任何检出计为误报（对比基线时硬失败）；
- 漏检会导致 `--compare` 失败；意外检出（detected - expected）仅报告不计败。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from main import run_audit  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"

VAMPI_MINI_FILES = {
    "config.py": "SECRET_KEY = 'random'\n",
    "api_views/books.py": (
        'from flask import request\n'
        'from app import db\n'
        '\n'
        'def get_all_books():\n'
        '    query = "SELECT * FROM books WHERE title = \'" + request.args.get("title") + "\'"\n'
        '    return db.execute(query)\n'
        '\n'
        'def get_book_by_id(book_id):\n'
        '    return db.execute("SELECT * FROM books WHERE id = %s" % book_id)\n'
    ),
    "api_views/users.py": (
        'from flask import request\n'
        'from app import db\n'
        '\n'
        'def register():\n'
        '    data = request.get_json()\n'
        '    user = User(username=data["username"], password=data["password"],\n'
        '                admin=data.get("admin", False))\n'
        '    db.add(user)\n'
        '\n'
        'def login():\n'
        '    data = request.get_json()\n'
        '    user = User.query.filter_by(username=data["username"]).first()\n'
        '    if data["password"] == user.password:\n'
        '        return "ok"\n'
        '    return "fail"\n'
    ),
}

SAFE_APP = (
    'from flask import request, abort\n'
    'from app import db, current_user\n'
    '\n'
    'def get_book(book_id):\n'
    '    row = db.execute("SELECT * FROM books WHERE id = ?", (book_id,))\n'
    '    if row.owner_id != current_user.id:\n'
    '        abort(403)\n'
    '    return row\n'
    '\n'
    'def register():\n'
    '    data = request.get_json()\n'
    '    if data["password"] == data["confirm"]:\n'
    '        user = User(username=data["username"], admin=False)\n'
    '        db.add(user)\n'
)

# 内置靶场集：expected 为植入的漏洞类型（ground truth），safe 集期望零检出。
BUILTIN_SETS = [
    {
        "label": "web-fixture",
        "files": {"vulnerable_app.py": (FIXTURES / "vulnerable_app.py").read_text(encoding="utf-8")},
        "expected": {
            "hardcoded_password", "api_key", "sql_injection", "xss",
            "command_injection", "path_traversal", "code_injection",
        },
        "safe": False,
    },
    {
        "label": "agent-fixture",
        "files": {"vulnerable_agent_app.py": (FIXTURES / "vulnerable_agent_app.py").read_text(encoding="utf-8")},
        "expected": {
            "prompt_injection", "mcp_insecurity", "excessive_agency",
            "hardcoded_password", "sql_injection",
        },
        "safe": False,
    },
    {
        "label": "vampi-mini",
        "files": VAMPI_MINI_FILES,
        "expected": {"sql_injection", "mass_assignment", "plaintext_password_comparison", "api_key"},
        "safe": False,
    },
    {
        "label": "safe-app",
        "files": {"app.py": SAFE_APP},
        "expected": set(),
        "safe": True,
    },
]


def _finding_types(result) -> set:
    """从 run_audit 结果中提取漏洞类型集合（兼容 dict / JSON 字符串）。"""
    if isinstance(result, str):
        result = json.loads(result)
    if not isinstance(result, dict):
        return set()
    types: set = set()
    for key in ("findings", "verified_findings"):
        items = result.get(key)
        if isinstance(items, list):
            types.update(str(item.get("vulnerability_type")) for item in items if isinstance(item, dict))
    return types


def _materialize(base: Path, files: dict) -> Path:
    for rel, content in files.items():
        target = base / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return base


async def measure_set(label: str, project_path: str, expected: set, safe: bool) -> dict:
    result = await run_audit(project_path=project_path, use_llm=False, output_format="json")
    detected = _finding_types(result)
    report = {
        "label": label,
        "safe_fixture": safe,
        "expected_types": sorted(expected),
        "detected_types": sorted(detected),
        "recall": round(len(expected & detected) / len(expected), 4) if expected else None,
        "missed_types": sorted(expected - detected),
        "unexpected_types": sorted(detected - expected),
    }
    return report


async def run_benchmark(extra_sets: list | None = None) -> dict:
    """执行全部内置与外部靶场集，返回汇总报告。"""
    from datetime import datetime, timezone

    reports = []
    workdir = Path(tempfile.mkdtemp(prefix="seismoscope-bench-"))
    try:
        for spec in BUILTIN_SETS + list(extra_sets or []):
            if "files" in spec:
                project = _materialize(workdir / spec["label"], spec["files"])
                project_path = str(project)
            else:
                project_path = spec["project_path"]
            reports.append(await measure_set(
                spec["label"], project_path, set(spec["expected"]), bool(spec.get("safe", False)),
            ))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    vulnerable_reports = [item for item in reports if not item["safe_fixture"]]
    safe_reports = [item for item in reports if item["safe_fixture"]]
    false_positives = sum(len(item["unexpected_types"]) for item in safe_reports)
    return {
        "contract_version": "seismoscope.benchmark-recall.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "deterministic-no-llm",
        "sets": reports,
        "summary": {
            "sets": len(reports),
            "mean_recall": round(
                sum(item["recall"] for item in vulnerable_reports) / len(vulnerable_reports), 4
            ) if vulnerable_reports else None,
            "safe_set_false_positives": false_positives,
        },
    }


def compare_with_baseline(current: dict, baseline: dict) -> list:
    """返回回归列表：召回下降或 safe 集出现误报。"""
    regressions = []
    base_sets = {item["label"]: item for item in baseline.get("sets", [])}
    for item in current.get("sets", []):
        previous = base_sets.get(item["label"])
        if not previous:
            continue
        if item["safe_fixture"]:
            if item["unexpected_types"]:
                regressions.append(f"{item['label']}: safe 靶场出现误报 {item['unexpected_types']}")
            continue
        if item["recall"] is not None and previous.get("recall") is not None \
                and item["recall"] < previous["recall"]:
            regressions.append(
                f"{item['label']}: 召回 {previous['recall']} -> {item['recall']}，漏检 {item['missed_types']}"
            )
    return regressions


def _render(report: dict) -> str:
    lines = [
        f"基准模式: {report['mode']}  生成时间: {report['generated_at']}",
        f"{'靶场集':<16}{'召回':>8}  漏检 / 意外检出",
        "-" * 72,
    ]
    for item in report["sets"]:
        recall = "—" if item["recall"] is None else f"{item['recall'] * 100:.0f}%"
        miss = ", ".join(item["missed_types"]) or "-"
        extra = ", ".join(item["unexpected_types"]) or "-"
        lines.append(f"{item['label']:<16}{recall:>8}  漏检[{miss}] 意外[{extra}]")
    summary = report["summary"]
    lines.append("-" * 72)
    lines.append(
        f"平均召回: {summary['mean_recall'] * 100:.0f}%  safe 集误报: {summary['safe_set_false_positives']}"
    )
    return "\n".join(lines)


def main() -> int:
    # Windows 传统控制台默认 cp1252/gbk，直接 print 中文表格会
    # UnicodeEncodeError；统一重配为 UTF-8（不可编码字符降级为替换符）。
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="靶场召回/误报基准")
    parser.add_argument("--json", help="结果写入的 JSON 文件路径")
    parser.add_argument("--compare", help="对比的历史基线 JSON，回归则退出码 1")
    parser.add_argument("--project", help="外部靶场项目路径（可多次，配合 --label/--expect）",
                        action="append", default=[])
    parser.add_argument("--label", help="外部靶场集标签（与 --project 按序对应）",
                        action="append", default=[])
    parser.add_argument("--expect", help="外部靶场预期漏洞类型，逗号分隔",
                        action="append", default=[])
    args = parser.parse_args()

    extra_sets = []
    for index, project in enumerate(args.project):
        label = args.label[index] if index < len(args.label) else f"external-{index + 1}"
        expected = set(
            value.strip()
            for value in (args.expect[index] if index < len(args.expect) else "").split(",")
            if value.strip()
        )
        extra_sets.append({"label": label, "project_path": project, "expected": expected, "safe": False})

    report = asyncio.run(run_benchmark(extra_sets))
    print(_render(report))

    if args.json:
        Path(args.json).write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"结果已写入 {args.json}")

    if args.compare:
        baseline = json.loads(Path(args.compare).read_text(encoding="utf-8"))
        regressions = compare_with_baseline(report, baseline)
        if regressions:
            print("\n检测到能力回退：", file=sys.stderr)
            for line in regressions:
                print(f"  - {line}", file=sys.stderr)
            return 1
        print("与基线对比：无回退")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
