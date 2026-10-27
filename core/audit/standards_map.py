"""漏洞类型到 CWE / OWASP 标准的映射。

用途：
- SARIF 输出的 rule 携带标准编号（tags）与 helpUri 直链，使
  GitHub Code Scanning 告警可直接跳转标准条目；
- 报告与整改画像引用行业标准编号，提升专业性。

条目为 (cwe_id | None, extra_tags)。CWE 缺席时（如提示词注入）
用 OWASP LLM Top 10 / API Top 10 标签补位，helpUri 指向 OWASP。
"""

from __future__ import annotations

from typing import Any

_CWE_BASE = "https://cwe.mitre.org/data/definitions/"
_OwASP_LLM = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
_OWASP_API = "https://owasp.org/www-project-api-security/"

#: 漏洞类型 -> (CWE 编号或 None, 附加标签)
VULNERABILITY_STANDARDS: dict[str, tuple] = {
    "sql_injection": ("CWE-89", ["owasp-api8-injection"]),
    "xss": ("CWE-79", ["owasp-api8-injection"]),
    "command_injection": ("CWE-78", ["owasp-api8-injection"]),
    "code_injection": ("CWE-94", ["owasp-api8-injection"]),
    "path_traversal": ("CWE-22", []),
    "ssrf": ("CWE-918", ["owasp-api8-injection"]),
    "unsafe_deserialization": ("CWE-502", []),
    "insecure_deserialization": ("CWE-502", []),
    "hardcoded_password": ("CWE-798", []),
    "api_key": ("CWE-798", []),
    "secret_leak": ("CWE-798", []),
    "credential_exposure": ("CWE-798", []),
    "hardcoded_secrets": ("CWE-798", []),
    "hardcoded_credentials": ("CWE-798", []),
    "mass_assignment": ("CWE-915", ["owasp-api1-bola"]),
    "idor": ("CWE-639", ["owasp-api1-bola"]),
    "authorization_bypass": ("CWE-862", ["owasp-api1-bola"]),
    "broken_access_control": ("CWE-862", []),
    "missing_authentication": ("CWE-306", ["owasp-api2-broken-authentication"]),
    "plaintext_password_comparison": ("CWE-256", ["owasp-api2-broken-authentication"]),
    "dependency_vulnerability": ("CWE-1395", []),
    "workflow_insecurity": ("CWE-78", ["supply-chain"]),
    "prompt_injection": (None, ["owasp-llm01-prompt-injection"]),
    "unsafe_output_handling": (None, ["owasp-llm05-improper-output-handling"]),
    "excessive_agency": (None, ["owasp-llm06-excessive-agency"]),
    "agent_insecurity": (None, ["owasp-llm"]),
    "context_manipulation": (None, ["owasp-llm"]),
    "mcp_insecurity": (None, ["mcp", "owasp-llm06-excessive-agency"]),
    "mcp_tool_poisoning": (None, ["mcp", "tool-poisoning"]),
    "tool_poisoning": (None, ["mcp", "tool-poisoning"]),
    "resource_exposure": (None, ["mcp"]),
    "denial_of_service": ("CWE-400", []),
}


#: VRTM 威胁技术 -> 标准映射（technique id 取自 threat_model.py 目录，勿凭空添加）
TECHNIQUE_STANDARDS: dict[str, tuple] = {
    "T-PROMPT-INJECTION": (None, ["owasp-llm01-prompt-injection"]),
    "T-INDIRECT-PROMPT-INJECTION": (None, ["owasp-llm01-prompt-injection"]),
    "T-RETRIEVAL-INJECTION": (None, ["owasp-llm01-prompt-injection"]),
    "T-MCP-DESCRIPTION-INJECTION": (None, ["mcp", "tool-poisoning", "owasp-llm01-prompt-injection"]),
    "T-EXCESSIVE-AGENCY": (None, ["owasp-llm06-excessive-agency"]),
    "T-UNPROTECTED-ENTRY": ("CWE-306", []),
    "T-MCP-AUTHORIZATION": ("CWE-862", ["mcp"]),
    "T-BROWSER-SINK-INJECTION": ("CWE-79", []),
    "T-WORKFLOW-PRIVILEGE": ("CWE-78", ["supply-chain"]),
    "T-SENSITIVE-STORAGE-ACCESS": ("CWE-312", []),
    "T-MEMORY-POISONING": (None, ["owasp-llm02-sensitive-information-disclosure"]),
    "T-SECRET-DELEGATION": ("CWE-798", []),
    "T-DEPLOYMENT-TAMPERING": ("CWE-494", ["supply-chain"]),
    "T-SERVICE-IDENTITY-OVERPRIVILEGE": ("CWE-250", []),
}


def technique_standards(technique_id: str) -> dict[str, Any] | None:
    """VRTM 技术的标准关联；未映射技术返回 None。"""
    entry = TECHNIQUE_STANDARDS.get(str(technique_id).strip().upper())
    if entry is None:
        return None
    cwe, extra_tags = entry
    tags = list(extra_tags)
    if cwe:
        tags.insert(0, cwe.lower())
        return {"id": cwe, "tags": tags, "help_uri": f"{_CWE_BASE}{cwe.split('-')[1]}.html"}
    return {"id": None, "tags": tags, "help_uri": _OwASP_LLM}


def standards_for(vulnerability_type: str) -> dict[str, Any] | None:
    """返回 {"id", "tags", "help_uri"}；未映射类型返回 None。"""
    entry = VULNERABILITY_STANDARDS.get(str(vulnerability_type).strip().lower())
    if entry is None:
        return None
    cwe, extra_tags = entry
    tags = list(extra_tags)
    if cwe:
        tags.insert(0, cwe.lower())
        return {"id": cwe, "tags": tags, "help_uri": f"{_CWE_BASE}{cwe.split('-')[1]}.html"}
    return {"id": None, "tags": tags, "help_uri": _OwASP_LLM if "llm" in " ".join(tags) or "mcp" in tags else _OWASP_API}
