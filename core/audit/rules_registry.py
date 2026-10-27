"""外置检测规则加载器：默认 YAML + 环境变量自定义 + 内置兜底。

设计：

- 默认规则 ``core/audit/rules/patterns.yml`` 随包分发（与 core 内置字典
  由 golden 测试强制同步）；社区/用户复制后增删规则，设置
  ``VIBE_SEC_RULES_PATH`` 指向自定义文件即可生效，无需改代码。
- 加载失败（文件缺失/损坏/结构非法）返回 ``None``，调用方回落到内置
  字典——规则文件损坏不得中断审计。
- 规则级校验：type 非空、severity 合法、patterns 为非空字符串列表；
  单条非法跳过并告警；全部条目非法按加载失败处理（回落内置）。
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

ENV_RULES_PATH = "VIBE_SEC_RULES_PATH"
RULE_GROUPS = (
    "web_vulnerability_patterns",
    "agent_vulnerability_patterns",
    "workflow_vulnerability_patterns",
    "secret_patterns",
)
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_MIN_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_DEFAULT_RULES_PATH = Path(__file__).resolve().parent / "rules" / "patterns.yml"


def _coerce_severity(value: str):
    """YAML 字符串 -> 严重级对象（与 audit_agent 的 Severity 兼容）。"""
    from agents.audit_agent import Severity

    return Severity(str(value).lower())


def _validate_rule(entry: Any, index: int) -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        logger.warning("规则 #%d 不是映射，已跳过", index)
        return None
    vuln_type = str(entry.get("vulnerability_type") or "").strip()
    severity = str(entry.get("severity") or "").strip().lower()
    patterns = entry.get("patterns")
    if not vuln_type or severity not in _VALID_SEVERITIES:
        logger.warning("规则 #%d（type=%s）type/severity 非法，已跳过", index, vuln_type or "?")
        return None
    if not isinstance(patterns, list) or not patterns or not all(
        isinstance(p, str) and p.strip() for p in patterns
    ):
        logger.warning("规则 %s 的 patterns 必须为非空字符串列表，已跳过", vuln_type)
        return None
    return {
        "vulnerability_type": vuln_type,
        "severity": severity,
        "description": str(entry.get("description") or f"自定义检测规则: {vuln_type}"),
        "patterns": [p for p in patterns],
    }


def load_pattern_rules(path: str | None = None) -> dict[str, list[dict[str, Any]]] | None:
    """读取并校验规则文件，返回 {组名: [规则]}；任何失败返回 None。"""
    import yaml

    target = Path(path or os.getenv(ENV_RULES_PATH) or _DEFAULT_RULES_PATH)
    try:
        document = yaml.safe_load(target.read_text(encoding="utf-8-sig"))
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("规则文件 %s 不可用（%s），回落内置规则", target, type(exc).__name__)
        return None
    if not isinstance(document, dict):
        logger.warning("规则文件 %s 结构非法，回落内置规则", target)
        return None

    result: dict[str, list[dict[str, Any]]] = {}
    valid_total = 0
    for group in RULE_GROUPS:
        entries = document.get(group) or []
        if not isinstance(entries, list):
            logger.warning("规则组 %s 非法（应为列表），该组回落内置", group)
            entries = []
        rules = []
        for index, entry in enumerate(entries):
            rule = _validate_rule(entry, index)
            if rule is not None:
                rules.append(rule)
        if rules:
            result[group] = rules
            valid_total += len(rules)
    if valid_total == 0:
        logger.warning("规则文件 %s 无有效条目，回落内置规则", target)
        return None
    return result


def as_agent_rule_map(rules: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """加载结果 -> audit_agent 使用的 {type: {patterns, severity, description}}。"""
    return {
        rule["vulnerability_type"]: {
            "patterns": rule["patterns"],
            "severity": _coerce_severity(rule["severity"]),
            "description": rule["description"],
        }
        for rule in rules
    }
