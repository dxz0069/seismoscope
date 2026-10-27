"""
Vibe Sec Platform — 智能体基础设施

包含 BaseAgent 基类、TaskHandoff 结构化交接、AgentResult 等核心数据结构。
借鉴 AutoCVE 的 base.py 设计，增加 context_refs 避免数据复制。
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Protocol

# ========== 枚举类型 ==========

class AgentType(Enum):
    """Agent 类型枚举"""
    ORCHESTRATOR = "orchestrator"
    RECON = "recon"
    SURFACE = "surface"
    AUDIT = "audit"
    VERIFICATION = "verification"
    REMEDIATION = "remediation"
    REGRESSION = "regression"


class AgentPattern(Enum):
    """Agent 模式枚举"""
    REACT = "react"  # 思考-行动-观察循环
    PLAN_AND_EXECUTE = "plan_execute"  # 计划-执行模式


class Severity(Enum):
    """漏洞严重性枚举"""
    CRITICAL = "critical"  # CVSS 9.0-10.0
    HIGH = "high"          # CVSS 7.0-8.9
    MEDIUM = "medium"      # CVSS 4.0-6.9
    LOW = "low"            # CVSS 0.1-3.9
    INFO = "info"          # 信息性


# ========== 核心数据结构 ==========

@dataclass
class AgentConfig:
    """Agent 配置"""
    name: str
    agent_type: AgentType
    pattern: AgentPattern = AgentPattern.REACT
    model: str | None = None  # LLM 模型标识
    temperature: float = 0.1
    max_tokens: int = 8192
    max_iterations: int = 20
    timeout_seconds: int = 600
    tools: list[str] = field(default_factory=list)
    system_prompt: str | None = None
    enabled: bool = True


@dataclass
class TaskHandoff:
    """
    智能体间结构化交接数据

    借鉴 AutoCVE 的 TaskHandoff 设计，增加 context_refs 字段
    通过 ID 引用避免数据复制，降低上下文长度。

    Attributes:
        from_agent: 发送方 Agent 类型
        to_agent: 接收方 Agent 类型
        summary: 摘要
        work_completed: 已完成工作清单
        key_findings: 关键发现（最多20个）
        insights: 洞察
        suggested_actions: 建议动作
        attention_points: 注意点
        priority_areas: 优先区域
        context_refs: ID 引用映射，避免数据复制
        confidence: 置信度 (0.0-1.0)
        timestamp: 时间戳
    """
    from_agent: str
    to_agent: str
    summary: str
    work_completed: list[str] = field(default_factory=list)
    key_findings: list[dict[str, Any]] = field(default_factory=list)
    insights: list[str] = field(default_factory=list)
    suggested_actions: list[dict[str, Any]] = field(default_factory=list)
    attention_points: list[str] = field(default_factory=list)
    priority_areas: list[str] = field(default_factory=list)
    context_refs: dict[str, str] = field(default_factory=dict)
    confidence: float = 0.8
    timestamp: datetime = field(default_factory=datetime.now)

    def to_prompt_context(self) -> str:
        """
        转换为 LLM 可理解的上下文文本

        Returns:
            格式化的 Markdown 字符串，可直接注入到 LLM prompt 中
        """
        lines = [
            f"## Handoff From {self.from_agent} Agent",
            "",
            "### Summary",
            self.summary,
            "",
        ]

        if self.work_completed:
            lines.append("### Completed Work")
            lines.extend(f"- {w}" for w in self.work_completed)
            lines.append("")

        if self.key_findings:
            lines.append("### Key Findings")
            for i, finding in enumerate(self.key_findings[:20], 1):
                severity = finding.get("severity", "medium").upper()
                title = finding.get("title", "Unknown")
                file_path = finding.get("file_path", "")
                lines.append(f"{i}. [{severity}] {title}")
                if file_path:
                    lines.append(f"   - File: `{file_path}`")
            lines.append("")

        if self.insights:
            lines.append("### Insights")
            lines.extend(f"- {item}" for item in self.insights)
            lines.append("")

        if self.suggested_actions:
            lines.append("### Suggested Actions")
            for action in self.suggested_actions:
                priority = action.get("priority", "medium").upper()
                description = action.get("description", "")
                lines.append(f"- [{priority}] {description}")
            lines.append("")

        if self.attention_points:
            lines.append("### Attention Points")
            lines.extend(f"- {point}" for point in self.attention_points)
            lines.append("")

        if self.priority_areas:
            lines.append("### Priority Areas")
            lines.extend(f"- {area}" for area in self.priority_areas)
            lines.append("")

        if self.context_refs:
            lines.append("### Context References")
            for key, ref_id in self.context_refs.items():
                lines.append(f"- {key}: `{ref_id}`")
            lines.append("")

        lines.append(f"**Confidence**: {self.confidence:.2f}")

        return "\n".join(lines)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaskHandoff":
        """从字典创建 TaskHandoff"""
        return cls(
            from_agent=data.get("from_agent", "unknown"),
            to_agent=data.get("to_agent", "unknown"),
            summary=data.get("summary", ""),
            work_completed=data.get("work_completed", []),
            key_findings=data.get("key_findings", []),
            insights=data.get("insights", []),
            suggested_actions=data.get("suggested_actions", []),
            attention_points=data.get("attention_points", []),
            priority_areas=data.get("priority_areas", []),
            context_refs=data.get("context_refs", {}),
            confidence=data.get("confidence", 0.8),
        )

    def to_dict(self) -> dict[str, Any]:
        """转换为字典"""
        return {
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "summary": self.summary,
            "work_completed": self.work_completed,
            "key_findings": self.key_findings,
            "insights": self.insights,
            "suggested_actions": self.suggested_actions,
            "attention_points": self.attention_points,
            "priority_areas": self.priority_areas,
            "context_refs": self.context_refs,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class AgentResult:
    """
    Agent 执行结果

    Attributes:
        success: 是否成功
        data: 结果数据
        metadata: 元数据（tokens_used, duration_ms 等）
        handoff: 传递给下一个 Agent 的 TaskHandoff
        tokens_used: 使用的 token 数量
    """
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    handoff: TaskHandoff | None = None
    tokens_used: int = 0

    @classmethod
    def success_result(
        cls,
        data: dict[str, Any],
        handoff: TaskHandoff | None = None,
        tokens_used: int = 0,
        **metadata
    ) -> "AgentResult":
        """创建成功结果"""
        return cls(
            success=True,
            data=data,
            metadata=metadata,
            handoff=handoff,
            tokens_used=tokens_used,
        )

    @classmethod
    def failure_result(
        cls,
        error: str,
        data: dict[str, Any] | None = None,
        **metadata
    ) -> "AgentResult":
        """创建失败结果"""
        return cls(
            success=False,
            data=data or {"error": error},
            metadata={**metadata, "error": error},
        )


# ========== LLM 服务接口 ==========

class LLMService(Protocol):
    """LLM 服务协议接口"""

    async def chat(
        self,
        messages: list[dict[str, str]],
        *,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        tools: list[dict] | None = None,
    ) -> dict[str, Any]:
        """
        发送聊天请求

        Args:
            messages: 消息列表
            model: 模型标识
            temperature: 温度参数
            max_tokens: 最大 token 数
            tools: 工具定义列表

        Returns:
            LLM 响应
        """
        ...


# ========== 工具接口 ==========

class ToolRegistry(Protocol):
    """工具注册表协议接口"""

    def get_tool(self, name: str) -> Optional["AgentTool"]:
        """获取工具"""
        ...

    def list_tools(self) -> list[str]:
        """列出所有工具名称"""
        ...


class AgentTool(Protocol):
    """智能体工具协议接口"""

    @property
    def name(self) -> str:
        """工具名称"""
        ...

    @property
    def description(self) -> str:
        """工具描述"""
        ...

    async def execute(self, **kwargs) -> dict[str, Any]:
        """执行工具"""
        ...


# ========== BaseAgent 基类 ==========

class BaseAgent(ABC):
    """
    所有 Agent 的基类

    提供统一的接口和基础设施支持。子类需要实现 run() 方法。

    Attributes:
        config: Agent 配置
        llm_service: LLM 服务
        tools: 工具注册表
        event_emitter: 事件发射器
    """

    def __init__(
        self,
        config: AgentConfig,
        llm_service: LLMService,
        tools: ToolRegistry | None = None,
        event_emitter: Callable | None = None,
    ):
        self.config = config
        self.llm_service = llm_service
        self.tools = tools
        self.event_emitter = event_emitter

    @abstractmethod
    async def run(self, payload: dict[str, Any]) -> AgentResult:
        """
        执行 Agent 主逻辑

        Args:
            payload: 输入数据

        Returns:
            AgentResult 执行结果
        """
        ...

    async def emit_event(self, event: str, message: str, metadata: dict | None = None):
        """
        发射事件

        Args:
            event: 事件类型
            message: 事件消息
            metadata: 事件元数据
        """
        if self.event_emitter:
            await self.event_emitter(
                event=event,
                message=message,
                metadata=metadata or {},
                agent_name=self.config.name,
                agent_type=self.config.agent_type.value,
            )

    async def call_llm(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        tools: list[dict] | None = None,
    ) -> dict[str, Any]:
        """
        调用 LLM

        Args:
            messages: 消息列表
            temperature: 温度参数（覆盖配置）
            max_tokens: 最大 token 数（覆盖配置）
            tools: 工具定义列表

        Returns:
            LLM 响应
        """
        return await self.llm_service.chat(
            messages=messages,
            model=self.config.model,
            temperature=temperature if temperature is not None else self.config.temperature,
            max_tokens=max_tokens if max_tokens is not None else self.config.max_tokens,
            tools=tools,
        )

    def get_tool(self, name: str) -> AgentTool | None:
        """获取工具"""
        if self.tools:
            return self.tools.get_tool(name)
        return None

    def list_tools(self) -> list[str]:
        """列出所有工具名称"""
        if self.tools:
            return self.tools.list_tools()
        return []

    def create_handoff(
        self,
        to_agent: str,
        summary: str,
        **kwargs
    ) -> TaskHandoff:
        """
        创建 TaskHandoff

        Args:
            to_agent: 目标 Agent 类型
            summary: 摘要
            **kwargs: 其他字段

        Returns:
            TaskHandoff 实例
        """
        return TaskHandoff(
            from_agent=self.config.agent_type.value,
            to_agent=to_agent,
            summary=summary,
            **kwargs,
        )
