"""
Vibe Sec Platform — Agent 注册中心

提供 Agent 的注册、发现、状态管理功能。
支持动态 Agent 树，子 Agent 可以有依赖关系。
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from .base import AgentType, BaseAgent

logger = logging.getLogger(__name__)


class AgentState(Enum):
    """Agent 状态枚举"""
    PENDING = "pending"      # 等待执行
    RUNNING = "running"      # 执行中
    COMPLETED = "completed"  # 已完成
    FAILED = "failed"        # 执行失败
    SKIPPED = "skipped"      # 已跳过


@dataclass
class AgentRegistration:
    """Agent 注册信息"""
    agent_type: AgentType
    agent_class: type
    dependencies: List[AgentType] = field(default_factory=list)
    enabled: bool = True
    priority: int = 0  # 优先级，数值越大优先级越高


class AgentRegistry:
    """
    Agent 注册中心

    管理所有 Agent 的注册、发现和状态跟踪。
    支持依赖关系解析和执行顺序计算。

    Example:
        registry = AgentRegistry()
        registry.register(AgentType.RECON, ReconAgent)
        registry.register(AgentType.SURFACE, SurfaceAgent, dependencies=[AgentType.RECON])

        # 获取执行顺序
        execution_order = registry.get_execution_order()
        # -> [AgentType.RECON, AgentType.SURFACE]
    """

    def __init__(self):
        self._registrations: Dict[AgentType, AgentRegistration] = {}
        self._instances: Dict[AgentType, BaseAgent] = {}
        self._states: Dict[AgentType, AgentState] = {}

    def register(
        self,
        agent_type: AgentType,
        agent_class: type,
        dependencies: Optional[List[AgentType]] = None,
        enabled: bool = True,
        priority: int = 0,
    ) -> None:
        """
        注册 Agent

        Args:
            agent_type: Agent 类型
            agent_class: Agent 类
            dependencies: 依赖的 Agent 类型列表
            enabled: 是否启用
            priority: 优先级

        Raises:
            ValueError: 如果 Agent 类型已注册
        """
        if agent_type in self._registrations:
            logger.warning(f"Agent {agent_type.value} already registered, overwriting")

        registration = AgentRegistration(
            agent_type=agent_type,
            agent_class=agent_class,
            dependencies=dependencies or [],
            enabled=enabled,
            priority=priority,
        )

        self._registrations[agent_type] = registration
        self._states[agent_type] = AgentState.PENDING

        logger.info(f"Registered agent: {agent_type.value}")

    def unregister(self, agent_type: AgentType) -> None:
        """
        取消注册 Agent

        Args:
            agent_type: Agent 类型
        """
        if agent_type in self._registrations:
            del self._registrations[agent_type]
            if agent_type in self._instances:
                del self._instances[agent_type]
            if agent_type in self._states:
                del self._states[agent_type]
            logger.info(f"Unregistered agent: {agent_type.value}")

    def get_registration(self, agent_type: AgentType) -> Optional[AgentRegistration]:
        """获取 Agent 注册信息"""
        return self._registrations.get(agent_type)

    def get_instance(self, agent_type: AgentType) -> Optional[BaseAgent]:
        """获取 Agent 实例"""
        return self._instances.get(agent_type)

    def set_instance(self, agent_type: AgentType, agent: BaseAgent) -> None:
        """设置 Agent 实例"""
        self._instances[agent_type] = agent

    def get_state(self, agent_type: AgentType) -> AgentState:
        """获取 Agent 状态"""
        return self._states.get(agent_type, AgentState.PENDING)

    def set_state(self, agent_type: AgentType, state: AgentState) -> None:
        """设置 Agent 状态"""
        self._states[agent_type] = state

    def list_agents(self, enabled_only: bool = False) -> List[AgentType]:
        """
        列出所有注册的 Agent 类型

        Args:
            enabled_only: 是否只返回启用的 Agent

        Returns:
            Agent 类型列表
        """
        if enabled_only:
            return [
                agent_type
                for agent_type, reg in self._registrations.items()
                if reg.enabled
            ]
        return list(self._registrations.keys())

    def get_enabled_agents(self) -> List[AgentType]:
        """获取所有启用的 Agent 类型"""
        return self.list_agents(enabled_only=True)

    def get_dependencies(self, agent_type: AgentType) -> List[AgentType]:
        """获取 Agent 的依赖列表"""
        reg = self._registrations.get(agent_type)
        return reg.dependencies if reg else []

    def get_execution_order(self) -> List[AgentType]:
        """
        获取 Agent 执行顺序（拓扑排序）

        基于依赖关系和优先级计算执行顺序。

        Returns:
            按依赖顺序排列的 Agent 类型列表

        Raises:
            ValueError: 如果存在循环依赖
        """
        # 只考虑启用的 Agent
        enabled_agents = set(self.get_enabled_agents())

        if not enabled_agents:
            return []

        # 构建依赖图
        graph: Dict[AgentType, Set[AgentType]] = {}
        in_degree: Dict[AgentType, int] = {}

        for agent_type in enabled_agents:
            graph[agent_type] = set()
            in_degree[agent_type] = 0

        for agent_type in enabled_agents:
            deps = self.get_dependencies(agent_type)
            for dep in deps:
                if dep in enabled_agents:
                    graph[dep].add(agent_type)
                    in_degree[agent_type] += 1

        # Kahn's 算法进行拓扑排序
        queue = [at for at in enabled_agents if in_degree[at] == 0]
        # 按优先级排序（优先级高的先执行）
        queue.sort(key=lambda at: self._registrations[at].priority, reverse=True)

        result = []
        while queue:
            current = queue.pop(0)
            result.append(current)

            for neighbor in graph[current]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
                    queue.sort(key=lambda at: self._registrations[at].priority, reverse=True)

        if len(result) != len(enabled_agents):
            missing = enabled_agents - set(result)
            raise ValueError(f"Circular dependency detected involving: {[at.value for at in missing]}")

        return result

    def check_dependencies_satisfied(self, agent_type: AgentType) -> bool:
        """
        检查 Agent 的依赖是否已满足

        Args:
            agent_type: Agent 类型

        Returns:
            依赖是否都已成功完成
        """
        deps = self.get_dependencies(agent_type)
        for dep in deps:
            if self.get_state(dep) != AgentState.COMPLETED:
                return False
        return True

    def reset_all_states(self) -> None:
        """重置所有 Agent 状态为 PENDING"""
        for agent_type in self._registrations:
            self._states[agent_type] = AgentState.PENDING

    def get_completed_agents(self) -> List[AgentType]:
        """获取所有已完成的 Agent 类型"""
        return [
            agent_type
            for agent_type, state in self._states.items()
            if state == AgentState.COMPLETED
        ]

    def get_failed_agents(self) -> List[AgentType]:
        """获取所有已失败的 Agent 类型"""
        return [
            agent_type
            for agent_type, state in self._states.items()
            if state == AgentState.FAILED
        ]

    def __contains__(self, agent_type: AgentType) -> bool:
        """检查 Agent 类型是否已注册"""
        return agent_type in self._registrations

    def __len__(self) -> int:
        """返回注册的 Agent 数量"""
        return len(self._registrations)
