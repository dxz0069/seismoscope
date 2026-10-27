"""LLM 语义通道验收工具的纯逻辑测试（不触网、不调用模型）。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "cve_replay_llm.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("cve_replay_llm", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _target():
    return json.loads((ROOT / "tests" / "regression_fixtures" / "cve_replay" / "manifest.json")
                      .read_text(encoding="utf-8"))["targets"][0]


def test_line_hits_uses_same_standard_as_static_replay():
    module = _load_module()
    target = _target()  # mistune，hunk_lines [1, 27]
    findings = [
        {"vulnerability_type": "path_traversal", "file_path": "src/mistune/directives/include.py",
         "line_start": 30},
        {"vulnerability_type": "path_traversal", "file_path": "src/mistune/directives/include.py",
         "line_start": 60},   # 超出 hunk±8
        {"vulnerability_type": "xss", "file_path": "src/mistune/directives/include.py",
         "line_start": 27},   # 类型不符
    ]
    hits = module.line_hits(findings, target)
    assert len(hits) == 1 and hits[0]["line_start"] == 30


def test_summarize_conclusion_matrix():
    module = _load_module()
    controls = ("mistune", "launch-editor", "systeminformation", "serialize-javascript")
    # 对照组全过 + 合成语义目标命中 => accept（当前 4 个 vendor 目标均已归对照组）
    assert module.summarize(
        [{"target": name, "hit": True} for name in controls]
        + [{"target": "future-semantic-target", "hit": True}]
    )["conclusion"] == "accept"
    # 对照组全过但语义未命中 => reject（诚实失败）
    summary = module.summarize(
        [{"target": name, "hit": True} for name in controls]
        + [{"target": "future-semantic-target", "hit": False}]
    )
    assert summary["conclusion"] == "reject" and summary["semantic_hits"] == 0
    assert "未通过本次验收" in summary["note"]
    # 对照组未全过 => inconclusive（LLM 运行不足以背书）
    summary = module.summarize([
        {"target": "mistune", "hit": False},
        {"target": "future-semantic-target", "hit": True},
    ])
    assert summary["conclusion"] == "inconclusive"
    assert "对照组" in summary["note"]


def test_summarize_all_controls_no_semantic_targets():
    module = _load_module()
    summary = module.summarize([
        {"target": t, "hit": True}
        for t in ("mistune", "launch-editor", "systeminformation", "serialize-javascript")
    ])
    assert summary["conclusion"] == "no-semantic-targets"
    assert summary["semantic_targets"] == 0


def test_missing_credentials_exit_code():
    import subprocess
    import sys

    env_key_names = ("VIBE_SEC_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY")
    import os

    env = os.environ.copy()
    for key in env_key_names:
        env.pop(key, None)
    completed = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True, text=True, encoding="utf-8", timeout=60,
        cwd=str(ROOT), env=env,
    )
    assert completed.returncode == 2
    assert "模型凭据" in completed.stderr
