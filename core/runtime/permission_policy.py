"""
Vibe Sec Platform — PermissionPolicy 权限策略引擎

基于 deny-list 的权限检查机制，控制审查过程中的权限边界。
借鉴 lz-secure 的 harness.py 设计。
"""

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PermissionCheckResult:
    """权限检查结果"""
    allowed: bool
    reason: str
    policy_applied: Optional[str] = None


class PermissionPolicy:
    """
    权限策略引擎

    基于 deny-list 的权限检查，支持：
    - 工具名黑名单
    - 工具名前缀黑名单
    - 域名白名单
    - 关键动作黑名单

    Example:
        policy = PermissionPolicy(
            denied_tools=["delete_file", "format_disk"],
            denied_tool_prefixes=["rm_", "destroy_"],
            allowed_domains=["example.com", "api.service.com"],
            denied_actions=["drop_database", "truncate_table"],
        )

        result = policy.check(
            tool_name="execute_command",
            target_url="https://example.com/api",
            critical_action="query_database",
        )

        if result.allowed:
            # 执行操作
        else:
            print(f"Blocked: {result.reason}")
    """

    def __init__(
        self,
        *,
        allowed_domains: Optional[List[str]] = None,
        denied_tools: Optional[List[str]] = None,
        denied_tool_prefixes: Optional[List[str]] = None,
        denied_actions: Optional[List[str]] = None,
        max_file_size_mb: float = 10.0,
        allow_network_access: bool = True,
        allow_file_write: bool = True,
    ):
        self.allowed_domains = tuple(allowed_domains or ())
        self.denied_tools = {t.lower() for t in (denied_tools or ())}
        self.denied_tool_prefixes = tuple(
            p.lower() for p in (denied_tool_prefixes or ())
        )
        self.denied_actions = {a.lower() for a in (denied_actions or ())}
        self.max_file_size_mb = max_file_size_mb
        self.allow_network_access = allow_network_access
        self.allow_file_write = allow_file_write

    def check(
        self,
        *,
        tool_name: str,
        target_url: str = "",
        critical_action: str = "",
        file_size_mb: float = 0.0,
    ) -> PermissionCheckResult:
        """
        检查权限

        Args:
            tool_name: 工具名称
            target_url: 目标 URL（可选）
            critical_action: 关键动作（可选）
            file_size_mb: 文件大小（MB，可选）

        Returns:
            PermissionCheckResult
        """
        lowered_tool = tool_name.lower()

        # 1. 检查工具黑名单
        if lowered_tool in self.denied_tools:
            return PermissionCheckResult(
                allowed=False,
                reason=f"Tool '{tool_name}' is in denied tools list",
                policy_applied="denied_tools",
            )

        # 2. 检查工具前缀黑名单
        if any(lowered_tool.startswith(p) for p in self.denied_tool_prefixes):
            return PermissionCheckResult(
                allowed=False,
                reason=f"Tool '{tool_name}' matches denied prefix pattern",
                policy_applied="denied_tool_prefixes",
            )

        # 3. 检查域名白名单（如果设置了白名单）
        if self.allowed_domains and target_url:
            if not any(self._match_domain(target_url, d) for d in self.allowed_domains):
                return PermissionCheckResult(
                    allowed=False,
                    reason=f"Domain not in allowed list: {target_url}",
                    policy_applied="allowed_domains",
                )

        # 4. 检查关键动作黑名单
        if critical_action and critical_action.lower() in self.denied_actions:
            return PermissionCheckResult(
                allowed=False,
                reason=f"Action '{critical_action}' is in denied actions list",
                policy_applied="denied_actions",
            )

        # 5. 检查网络访问权限
        if target_url and not self.allow_network_access:
            return PermissionCheckResult(
                allowed=False,
                reason="Network access is disabled",
                policy_applied="allow_network_access",
            )

        # 6. 检查文件写入权限
        if "write" in lowered_tool and not self.allow_file_write:
            return PermissionCheckResult(
                allowed=False,
                reason="File write operations are disabled",
                policy_applied="allow_file_write",
            )

        # 7. 检查文件大小限制
        if file_size_mb > self.max_file_size_mb:
            return PermissionCheckResult(
                allowed=False,
                reason=f"File size {file_size_mb}MB exceeds limit {self.max_file_size_mb}MB",
                policy_applied="max_file_size_mb",
            )

        # 所有检查通过
        return PermissionCheckResult(
            allowed=True,
            reason="All permission checks passed",
        )

    def _match_domain(self, url: str, domain: str) -> bool:
        """检查 URL 是否匹配域名"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            return hostname == domain or hostname.endswith(f".{domain}")
        except Exception:
            return False

    def add_denied_tool(self, tool_name: str) -> None:
        """添加禁止的工具"""
        self.denied_tools.add(tool_name.lower())

    def add_denied_prefix(self, prefix: str) -> None:
        """添加禁止的工具前缀"""
        self.denied_tool_prefixes = self.denied_tool_prefixes + (prefix.lower(),)

    def add_allowed_domain(self, domain: str) -> None:
        """添加允许的域名"""
        self.allowed_domains = self.allowed_domains + (domain,)

    def add_denied_action(self, action: str) -> None:
        """添加禁止的动作"""
        self.denied_actions.add(action.lower())

    def get_summary(self) -> Dict[str, any]:
        """获取策略摘要"""
        return {
            "allowed_domains": list(self.allowed_domains),
            "denied_tools_count": len(self.denied_tools),
            "denied_prefixes_count": len(self.denied_tool_prefixes),
            "denied_actions_count": len(self.denied_actions),
            "max_file_size_mb": self.max_file_size_mb,
            "allow_network_access": self.allow_network_access,
            "allow_file_write": self.allow_file_write,
        }


# 预定义的安全策略
STRICT_POLICY = PermissionPolicy(
    denied_tools=[
        "delete_file", "format_disk", "drop_database",
        "truncate_table", "destroy_instance",
    ],
    denied_tool_prefixes=["rm_", "destroy_", "drop_", "delete_"],
    allowed_domains=[
        "api.openai.com",
        "api.anthropic.com",
        "github.com",
    ],
    denied_actions=[
        "drop_database", "truncate_table", "delete_all",
        "format_disk", "destroy_instance",
    ],
    max_file_size_mb=5.0,
    allow_network_access=True,
    allow_file_write=True,
)

MODERATE_POLICY = PermissionPolicy(
    denied_tools=[
        "format_disk", "drop_database",
    ],
    denied_tool_prefixes=["destroy_"],
    allowed_domains=[],  # 不限制域名
    denied_actions=[
        "drop_database", "destroy_instance",
    ],
    max_file_size_mb=50.0,
    allow_network_access=True,
    allow_file_write=True,
)

PERMISSIVE_POLICY = PermissionPolicy(
    denied_tools=[],
    denied_tool_prefixes=[],
    allowed_domains=[],
    denied_actions=[],
    max_file_size_mb=100.0,
    allow_network_access=True,
    allow_file_write=True,
)
