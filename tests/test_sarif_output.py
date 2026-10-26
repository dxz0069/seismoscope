"""SARIF 2.1.0 输出格式（OASIS 标准 / GitHub Code Scanning 互操作）。"""

from __future__ import annotations

import json

from core.reporting.output_formatter import OutputFormatter


def _sample_result() -> dict:
    return {
        "findings": [
            {
                "id": "sql-1",
                "vulnerability_type": "sql_injection",
                "severity": "high",
                "description": "可能的 SQL 注入：用户输入直接拼接到查询中",
                "file_path": "api_views\\books.py",
                "line_start": 6,
                "line_end": 6,
                "verification_status": "needs_evidence",
                "confidence": 0.7,
            },
            {
                "id": "pwd-1",
                "vulnerability_type": "plaintext_password_comparison",
                "severity": "medium",
                "description": "可能的明文密码比较",
                "file_path": "api_views/users.py",
                "line_start": 18,
                "line_end": 18,
            },
        ]
    }


def test_sarif_document_shape():
    document = json.loads(OutputFormatter().format(_sample_result(), "sarif"))
    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-schema-2.1.0.json")
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"].startswith("Seismoscope")
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {
        "sql_injection", "plaintext_password_comparison",
    }
    assert len(run["results"]) == 2


def test_sarif_result_mapping():
    document = json.loads(OutputFormatter().format(_sample_result(), "sarif"))
    by_rule = {item["ruleId"]: item for item in document["runs"][0]["results"]}

    sqli = by_rule["sql_injection"]
    assert sqli["level"] == "error", "high 严重级应映射为 error"
    assert "verification: needs_evidence" in sqli["message"]["text"]
    assert sqli["properties"]["verification_status"] == "needs_evidence"
    # Windows 路径归一化为 SARIF 要求的 URI 正斜杠形态
    assert sqli["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "api_views/books.py"
    assert sqli["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    assert sqli["locations"][0]["physicalLocation"]["region"]["startLine"] == 6
    assert sqli["partialFingerprints"]["seismoscopeFindingId/v1"] == "sql-1"

    pwd = by_rule["plaintext_password_comparison"]
    assert pwd["level"] == "warning", "medium 严重级应映射为 warning"
    assert "properties" not in pwd, "缺失字段不应输出空 properties"


def test_sarif_empty_findings_still_valid():
    document = json.loads(OutputFormatter().format({"findings": []}, "sarif"))
    assert document["runs"][0]["results"] == []
    assert document["runs"][0]["tool"]["driver"]["rules"] == []
