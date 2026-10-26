"""基准脚本本身的冒烟与回归判定逻辑测试。"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "benchmark_recall.py"


def _load_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location("benchmark_recall", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_benchmark_cli_all_green(tmp_path):
    """端到端冒烟：四个内置靶场集全部通过且 safe 零误报。"""
    output = tmp_path / "baseline.json"
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--json", str(output)],
        capture_output=True, text=True, timeout=300, cwd=str(ROOT),
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["contract_version"] == "seismoscope.benchmark-recall.v1"
    assert report["summary"]["mean_recall"] == 1.0
    assert report["summary"]["safe_set_false_positives"] == 0
    assert {item["label"] for item in report["sets"]} == {
        "web-fixture", "agent-fixture", "vampi-mini", "safe-app",
    }


def test_compare_flags_recall_regression_but_not_improvement():
    module = _load_module()
    baseline_set = {
        "label": "vampi-mini", "safe_fixture": False,
        "recall": 1.0, "missed_types": [], "unexpected_types": [],
    }
    current = {
        "sets": [
            dict(baseline_set, recall=0.75, missed_types=["mass_assignment"]),
        ]
    }
    baseline = {"sets": [baseline_set]}
    regressions = module.compare_with_baseline(current, baseline)
    assert len(regressions) == 1 and "召回" in regressions[0]

    improved = {"sets": [dict(baseline_set, recall=1.0)]}
    assert module.compare_with_baseline(improved, baseline) == []


def test_compare_flags_safe_set_false_positive():
    module = _load_module()
    baseline = {"sets": [{
        "label": "safe-app", "safe_fixture": True,
        "recall": None, "missed_types": [], "unexpected_types": [],
    }]}
    current = {"sets": [{
        "label": "safe-app", "safe_fixture": True,
        "recall": None, "missed_types": [], "unexpected_types": ["sql_injection"],
    }]}
    regressions = module.compare_with_baseline(current, baseline)
    assert len(regressions) == 1 and "误报" in regressions[0]
