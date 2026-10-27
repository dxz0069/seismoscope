"""
Vibe Sec Platform — 多格式输出报告生成器

支持多种输出格式：
1. Markdown - 人类可读的报告
2. JSON - 结构化数据
3. Claude Code - Claude Code 原生格式（适合智能体直接应用）
4. HTML - 网页报告
"""

import json
from datetime import datetime
from typing import Any, Dict

from ..audit.standards_map import standards_for


def _tool_version() -> str:
    """读取安装版本号（开发环境未安装时返回 dev）。"""
    try:
        from importlib.metadata import version

        return version("seismoscope")
    except Exception:  # pragma: no cover - 未安装场景
        return "dev"


class OutputFormatter:
    """
    多格式输出格式化器

    支持将审查结果转换为不同格式的输出。
    """

    def __init__(self):
        self.formatters = {
            "markdown": self.format_markdown,
            "json": self.format_json,
            "claude_code": self.format_claude_code,
            "html": self.format_html,
            "sarif": self.format_sarif,
        }

    def format(self, result: Dict[str, Any], format_type: str = "markdown") -> str:
        """
        格式化审查结果

        Args:
            result: 审查结果数据
            format_type: 输出格式类型

        Returns:
            格式化后的字符串
        """
        formatter = self.formatters.get(format_type)
        if not formatter:
            raise ValueError(f"Unsupported format: {format_type}. Available: {list(self.formatters.keys())}")

        return formatter(result)

    def format_markdown(self, result: Dict[str, Any]) -> str:
        """格式化为 Markdown"""
        lines = [
            "# Vibe Sec 安全审查报告",
            "",
            f"**审查时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]

        # 摘要
        findings = result.get("findings", [])
        if findings:
            lines.append("## 审查摘要")
            lines.append("")
            lines.append(f"共发现 **{len(findings)}** 个漏洞")
            lines.append("")

            # 按严重性统计
            severity_counts = {}
            for f in findings:
                severity = f.get("severity", "unknown")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            lines.append("**严重性分布**:")
            lines.append("")
            for severity in ["critical", "high", "medium", "low", "info"]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    lines.append(f"- {severity.upper()}: {count}")
            lines.append("")

            # 按漏洞类型统计
            type_counts = {}
            for f in findings:
                vtype = f.get("vulnerability_type", "unknown")
                type_counts[vtype] = type_counts.get(vtype, 0) + 1

            lines.append("**漏洞类型分布**:")
            lines.append("")
            for vtype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"- {vtype}: {count}")
            lines.append("")

            # 详细发现
            lines.append("## 详细发现")
            lines.append("")

            for i, finding in enumerate(findings, 1):
                severity = finding.get("severity", "unknown").upper()
                title = finding.get("title", finding.get("description", "未知漏洞"))
                file_path = finding.get("file_path", "未知")
                line_start = finding.get("line_start", "")
                confidence = finding.get("confidence", 0)
                vtype = finding.get("vulnerability_type", "unknown")

                lines.append(f"### {i}. [{severity}] {title}")
                lines.append("")
                lines.append(f"- **类型**: {vtype}")
                lines.append(f"- **文件**: `{file_path}`")
                if line_start:
                    lines.append(f"- **行号**: {line_start}-{finding.get('line_end', '')}")
                lines.append(f"- **置信度**: {confidence:.2f}")
                lines.append("")

                # 证据
                evidence = finding.get("evidence", [])
                if evidence:
                    lines.append("#### 证据")
                    lines.append("")
                    for ev in evidence:
                        ev_type = ev.get("type", "unknown")
                        if ev_type == "code_snippet":
                            lines.append(f"```python\n{ev.get('content', '')}\n```")
                        elif ev_type == "llm_analysis":
                            lines.append(f"- **LLM 分析**: {ev.get('explanation', '')}")
                            if ev.get("fix_suggestion"):
                                lines.append(f"- **修复建议**: {ev.get('fix_suggestion', '')}")
                    lines.append("")

        else:
            lines.append("未发现漏洞 ✅")
            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append("*报告由 Vibe Sec Platform 自动生成*")

        return "\n".join(lines)

    def format_json(self, result: Dict[str, Any]) -> str:
        """格式化为 JSON"""
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

    def format_sarif(self, result: Dict[str, Any]) -> str:
        """格式化为 SARIF 2.1.0（OASIS 标准，GitHub Code Scanning 原生支持）。

        映射约定：漏洞类型 -> ruleId，severity -> level（critical/high -> error，
        medium -> warning，其余 -> note），三态验证状态放入 result.properties，
        finding id 作为 partialFingerprints 供 Code Scanning 去重。
        """
        level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        rules: Dict[str, Dict[str, Any]] = {}
        results = []
        for finding in result.get("findings", []):
            vuln_type = str(finding.get("vulnerability_type", "unknown"))
            description = str(finding.get("description") or finding.get("title") or vuln_type)
            if vuln_type not in rules:
                standards = standards_for(vuln_type)
                rule: Dict[str, Any] = {
                    "id": vuln_type,
                    "shortDescription": {"text": description},
                    "properties": {"tags": ["security", "vibe-coding"]},
                }
                if standards:
                    rule["helpUri"] = standards["help_uri"]
                    rule["properties"]["tags"].extend(standards["tags"])
                rules[vuln_type] = rule
            message = description
            verification = finding.get("verification_status")
            if verification:
                message += f" [verification: {verification}]"
            file_path = str(finding.get("file_path") or "").replace("\\", "/")
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": int(finding.get("line_start") or 1),
                        "endLine": int(finding.get("line_end") or finding.get("line_start") or 1),
                    },
                }
            }
            sarif_result: Dict[str, Any] = {
                "ruleId": vuln_type,
                "level": level_map.get(str(finding.get("severity", "medium")).lower(), "note"),
                "message": {"text": message},
                "locations": [{"physicalLocation": location["physicalLocation"]}],
            }
            properties = {
                key: finding[key]
                for key in ("verification_status", "verification_level", "lane", "confidence")
                if finding.get(key) is not None
            }
            if properties:
                sarif_result["properties"] = properties
            if finding.get("id"):
                sarif_result["partialFingerprints"] = {"seismoscopeFindingId/v1": str(finding["id"])}
            results.append(sarif_result)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Seismoscope (vibe-sec)",
                        "informationUri": "https://github.com/dxz0069/seismoscope",
                        "semanticVersion": _tool_version(),
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False, default=str)

    def format_claude_code(self, result: Dict[str, Any]) -> str:
        """
        格式化为 Claude Code 原生格式

        这种格式适合 Claude Code 智能体直接应用修复。
        """
        lines = [
            "# Vibe Sec Security Audit Results",
            "",
            "## Summary",
            "",
        ]

        findings = result.get("findings", [])
        if not findings:
            lines.append("No vulnerabilities found. The code appears to be secure.")
            return "\n".join(lines)

        lines.append(f"Found **{len(findings)}** vulnerabilities that need attention:")
        lines.append("")

        # 按严重性分组
        critical_findings = [f for f in findings if f.get("severity") == "critical"]
        high_findings = [f for f in findings if f.get("severity") == "high"]
        medium_findings = [f for f in findings if f.get("severity") == "medium"]
        low_findings = [f for f in findings if f.get("severity") == "low"]

        if critical_findings:
            lines.append("### [CRITICAL] Critical Issues (Must Fix)")
            lines.append("")
            for i, f in enumerate(critical_findings, 1):
                lines.append(f"**{i}. {f.get('title', 'Critical Issue')}**")
                lines.append(f"- File: `{f.get('file_path')}`")
                lines.append(f"- Line: {f.get('line_start')}")
                lines.append(f"- Type: {f.get('vulnerability_type')}")
                lines.append(f"- Fix: {self._generate_fix_instruction(f)}")
                lines.append("")

        if high_findings:
            lines.append("### [HIGH] High Priority Issues")
            lines.append("")
            for i, f in enumerate(high_findings, 1):
                lines.append(f"**{i}. {f.get('title', 'High Issue')}**")
                lines.append(f"- File: `{f.get('file_path')}`")
                lines.append(f"- Line: {f.get('line_start')}")
                lines.append(f"- Fix: {self._generate_fix_instruction(f)}")
                lines.append("")

        if medium_findings:
            lines.append("### [MEDIUM] Medium Priority Issues")
            lines.append("")
            for i, f in enumerate(medium_findings, 1):
                lines.append(f"**{i}. {f.get('title', 'Medium Issue')}**")
                lines.append(f"- File: `{f.get('file_path')}`")
                lines.append(f"- Fix: {self._generate_fix_instruction(f)}")
                lines.append("")

        if low_findings:
            lines.append("### [LOW] Low Priority Issues")
            lines.append("")
            for i, f in enumerate(low_findings, 1):
                lines.append(f"**{i}. {f.get('title', 'Low Issue')}**")
                lines.append(f"- Fix: {self._generate_fix_instruction(f)}")
                lines.append("")

        # 添加修复建议
        returned_packages = result.get("returned_packages", [])
        if returned_packages:
            lines.append("## Remediation Packages")
            lines.append("")
            for package in returned_packages:
                finding = package.get("finding", {})
                remediation = package.get("remediation", {})
                lines.append(
                    f"### {remediation.get('package_id', 'REMEDIATION-unknown')}: {finding.get('title', 'Finding')}"
                )
                lines.append("")
                lines.append("```text")
                lines.append(remediation.get("ai_patch_prompt", ""))
                lines.append("```")
                lines.append("")
                criteria = remediation.get("acceptance_criteria", [])
                if criteria:
                    lines.append("Acceptance criteria:")
                    lines.extend(f"- {criterion}" for criterion in criteria)
                    lines.append("")

        lines.append("## Recommended Actions")
        lines.append("")
        lines.append("1. Fix all critical and high priority issues immediately")
        lines.append("2. Review medium priority issues and plan fixes")
        lines.append("3. Consider low priority issues for future improvements")
        lines.append("")
        lines.append("For detailed remediation guidance, refer to:")
        lines.append("- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)")
        lines.append("- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/security)")

        return "\n".join(lines)

    def _generate_fix_instruction(self, finding: Dict[str, Any]) -> str:
        """生成修复指令"""
        vtype = finding.get("vulnerability_type", "")

        fix_map = {
            "sql_injection": "Use parameterized queries instead of string concatenation",
            "command_injection": "Avoid shell=True and use secure command execution methods",
            "xss": "Sanitize and escape user input before rendering",
            "path_traversal": "Validate and sanitize file paths, use allowlists",
            "hardcoded_password": "Move credentials to environment variables or secure vault",
            "prompt_injection": "Use input validation, separate user content from system prompts",
            "mcp_insecurity": "Implement proper access controls and confirmation mechanisms",
            "excessive_agency": "Add human-in-the-loop for destructive operations, implement rate limiting",
        }

        return fix_map.get(vtype, "Review and fix the security issue")

    def format_html(self, result: Dict[str, Any]) -> str:
        """格式化为 HTML"""
        findings = result.get("findings", [])

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vibe Sec 安全审查报告</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
        }}
        .summary {{
            background-color: #e7f3ff;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .finding {{
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
        }}
        .finding.critical {{
            border-left: 4px solid #dc3545;
        }}
        .finding.high {{
            border-left: 4px solid #fd7e14;
        }}
        .finding.medium {{
            border-left: 4px solid #ffc107;
        }}
        .finding.low {{
            border-left: 4px solid #28a745;
        }}
        .severity {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }}
        .severity.critical {{
            background-color: #dc3545;
        }}
        .severity.high {{
            background-color: #fd7e14;
        }}
        .severity.medium {{
            background-color: #ffc107;
            color: #333;
        }}
        .severity.low {{
            background-color: #28a745;
        }}
        .file-path {{
            font-family: 'Courier New', monospace;
            background-color: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
        }}
        .evidence {{
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
        }}
        .stats {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin: 20px 0;
        }}
        .stat-card {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            min-width: 150px;
            text-align: center;
        }}
        .stat-number {{
            font-size: 32px;
            font-weight: bold;
            color: #007bff;
        }}
        .stat-label {{
            font-size: 14px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Vibe Sec 安全审查报告</h1>
        <p><strong>审查时间</strong>: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <div class="summary">
            <h2>📊 审查摘要</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{len(findings)}</div>
                    <div class="stat-label">总漏洞数</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len([f for f in findings if f.get('severity') == 'critical'])}</div>
                    <div class="stat-label">严重</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len([f for f in findings if f.get('severity') == 'high'])}</div>
                    <div class="stat-label">高危</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len([f for f in findings if f.get('severity') == 'medium'])}</div>
                    <div class="stat-label">中危</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len([f for f in findings if f.get('severity') == 'low'])}</div>
                    <div class="stat-label">低危</div>
                </div>
            </div>
        </div>

        <h2>🔍 详细发现</h2>
"""

        if not findings:
            html += "<p style='color: #28a745; font-size: 18px;'>✅ 未发现漏洞，代码安全！</p>"
        else:
            for i, finding in enumerate(findings, 1):
                severity = finding.get("severity", "unknown")
                title = finding.get("title", "未知漏洞")
                file_path = finding.get("file_path", "未知")
                line_start = finding.get("line_start", "")
                confidence = finding.get("confidence", 0)
                vtype = finding.get("vulnerability_type", "unknown")

                html += f"""
        <div class="finding {severity}">
            <h3>{i}. <span class="severity {severity}">{severity.upper()}</span> {title}</h3>
            <p><strong>类型</strong>: {vtype}</p>
            <p><strong>文件</strong>: <span class="file-path">{file_path}:{line_start}</span></p>
            <p><strong>置信度</strong>: {confidence:.2f}</p>
"""

                # 证据
                evidence = finding.get("evidence", [])
                if evidence:
                    html += "<div class='evidence'>\n"
                    for ev in evidence:
                        if ev.get("type") == "code_snippet":
                            html += f"<pre>{ev.get('content', '')}</pre>\n"
                    html += "</div>\n"

                html += "</div>\n"

        html += """
        <hr>
        <p style="text-align: center; color: #666; margin-top: 30px;">
            <em>报告由 Vibe Sec Platform 自动生成</em>
        </p>
    </div>
</body>
</html>"""

        return html
