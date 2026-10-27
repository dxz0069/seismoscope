"""威胁建模增强：假设标准关联、SARIF 汇流、未知分组导出。"""

from __future__ import annotations

import json

from core.audit.standards_map import technique_standards
from core.reporting.output_formatter import OutputFormatter


def test_technique_standards_cover_catalog_without_fabrication():
    from core.surface.threat_model import RuntimeThreatModelAnalyzer

    catalog_ids = {t.technique_id for t in RuntimeThreatModelAnalyzer.TECHNIQUES}
    mapped_ids = set(technique_standards.__globals__["TECHNIQUE_STANDARDS"])
    assert catalog_ids == mapped_ids, "映射表必须与 threat_model 目录逐 id 对齐（新增技术须同步映射）"


def test_technique_standards_shapes():
    mapped = technique_standards("T-PROMPT-INJECTION")
    assert mapped and mapped["id"] is None
    assert "owasp-llm01-prompt-injection" in mapped["tags"]
    entry = technique_standards("T-UNPROTECTED-ENTRY")
    assert entry["id"] == "CWE-306"
    assert entry["help_uri"].endswith("306.html")
    assert technique_standards("T-NOT-A-TECHNIQUE") is None


def _result_with_hypothesis():
    return {
        "findings": [],
        "threat_model": {
            "hypotheses": [
                {
                    "technique_id": "T-PROMPT-INJECTION",
                    "title": "External instructions can reach prompt",
                    "status": "open",
                    "confidence": 0.72,
                    "source_node_ids": ["ext-1"],
                    "attack_path": ["ext-1", "prompt-1"],
                    "standards": technique_standards("T-PROMPT-INJECTION"),
                },
            ]
        },
        "runtime_surface_graph": {
            "nodes": [
                {"id": "ext-1", "type": "external_content",
                 "attributes": {"file_path": "agent/chat.py", "line_start": 7}},
                {"id": "prompt-1", "type": "prompt",
                 "attributes": {"file_path": "agent/chat.py", "line_start": 9}},
            ]
        },
    }


def test_sarif_includes_vrtm_hypotheses_as_notes():
    document = json.loads(OutputFormatter().format(_result_with_hypothesis(), "sarif"))
    run = document["runs"][0]
    hypothesis_results = [r for r in run["results"] if r.get("properties", {}).get("kind") == "vrtm-hypothesis"]
    assert len(hypothesis_results) == 1
    item = hypothesis_results[0]
    assert item["level"] == "note", "假设是威胁建模信息，不得与 finding 同级"
    assert item["ruleId"] == "T-PROMPT-INJECTION"
    assert "[VRTM hypothesis/open]" in item["message"]["text"]
    assert item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "agent/chat.py"
    assert item["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
    rule = {r["id"]: r for r in run["tool"]["driver"]["rules"]}["T-PROMPT-INJECTION"]
    assert "vrtm-hypothesis" in rule["properties"]["tags"]
    assert "owasp-llm01-prompt-injection" in rule["properties"]["tags"]
    assert rule["helpUri"].startswith("https://owasp.org/")


def test_sarif_hypothesis_without_location_is_still_valid():
    result = _result_with_hypothesis()
    result["runtime_surface_graph"] = {"nodes": []}
    document = json.loads(OutputFormatter().format(result, "sarif"))
    hypothesis_results = [r for r in document["runs"][0]["results"] if r.get("properties", {}).get("kind") == "vrtm-hypothesis"]
    assert hypothesis_results and "locations" not in hypothesis_results[0]


def test_markdown_unknowns_grouped_by_kind():
    from core.vrtm.exporters import export_vrtm

    result = {
        "graph": {"metadata": {"coverage": {"unknowns": [
            {"kind": "authorization", "node_id": f"n{i}"} for i in range(4)
        ] + [{"kind": "transport", "node_id": "t1"}]}}},
        "threat_model": {},
    }
    markdown = export_vrtm(result, "markdown")
    assert "`authorization` × 4" in markdown
    assert "`transport` × 1" in markdown
    assert "… +1" in markdown, "超过 3 个样本时折叠显示"
