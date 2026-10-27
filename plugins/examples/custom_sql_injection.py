"""
示例插件：自定义漏洞检测规则

演示如何创建一个自定义的漏洞检测插件
"""

from typing import Any, Dict, List

from core.plugin import (
    DetectionRulePlugin,
    PluginMetadata,
    PluginType,
)


class CustomSQLInjectionPlugin(DetectionRulePlugin):
    """自定义 SQL 注入检测规则"""

    metadata = PluginMetadata(
        name="custom_sql_injection",
        version="1.0.0",
        author="VibeSec Team",
        description="自定义 SQL 注入检测规则，支持更多数据库方言",
        plugin_type=PluginType.DETECTION_RULE,
        supported_vuln_types=["sql_injection"],
        dependencies=[],
        config_schema={
            "strict_mode": {
                "type": "boolean",
                "default": False,
                "description": "严格模式，检测更多潜在漏洞"
            }
        }
    )

    async def initialize(self) -> None:
        """初始化插件"""
        self.strict_mode = self.get_config("strict_mode", False)
        self._initialized = True

    async def detect(self, code: str, context: dict[str, Any]) -> list[dict[str, Any]]:
        """检测 SQL 注入漏洞"""
        findings = []

        # 自定义检测逻辑
        patterns = [
            # PostgreSQL 特定的 SQL 注入模式
            r"execute\([^)]*\$[^)]*\)",
            # MySQL 特定的 SQL 注入模式
            r"query\([^)]*%[^)]*\)",
            # SQLite 特定的 SQL 注入模式
            r"executescript\([^)]*\+[^)]*\)",
        ]

        if self.strict_mode:
            # 严格模式下检测更多模式
            patterns.extend([
                r"cursor\.execute\([^)]*format[^)]*\)",
                r"\.raw\([^)]*f['\"]",
            ])

        import re
        for pattern in patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                findings.append({
                    "vulnerability_type": "sql_injection",
                    "severity": "high",
                    "confidence": 0.85,
                    "title": "SQL 注入风险（自定义规则）",
                    "description": f"检测到潜在的 SQL 注入模式：{match.group()}",
                    "line_start": line_num,
                    "line_end": line_num,
                    "evidence": [
                        {
                            "type": "code_snippet",
                            "content": match.group(),
                            "line": line_num,
                        }
                    ],
                    "plugin": self.metadata.name,
                })

        return findings

    async def cleanup(self) -> None:
        """清理资源"""
        pass
