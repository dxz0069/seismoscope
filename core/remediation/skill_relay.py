"""
Vibe Sec Platform — Skill Relay 状态机

追踪整改包在 AI 助手和平台之间的流转状态。
借鉴 lz-secure 的 skill_relay_delivery.py 设计。

状态流转：
draft → dispatched → acknowledged → in_progress → completed → returned
                         ↓                ↓              ↓
                      (AI接收)         (AI开始修复)   (AI完成修复)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime
import logging


logger = logging.getLogger(__name__)


class RelayState(Enum):
    """整改包流转状态"""
    DRAFT = "draft"                       # 草稿：整改包已生成
    DISPATCHED = "dispatched"             # 已分发：发送给 AI 助手
    ACKNOWLEDGED = "acknowledged"         # 已确认：AI 助手已接收
    IN_PROGRESS = "in_progress"           # 进行中：AI 助手正在修复
    COMPLETED = "completed"               # 已完成：AI 助手完成修复
    RETURNED = "returned"                 # 已返回：修复结果已返回平台
    REJECTED = "rejected"                 # 已拒绝：AI 助手拒绝修复
    FAILED = "failed"                     # 已失败：修复失败


@dataclass
class RelayEvent:
    """状态流转事件"""
    from_state: RelayState
    to_state: RelayState
    timestamp: datetime
    actor: str  # "system", "ai_assistant", "user"
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "message": self.message,
            "metadata": self.metadata,
        }


@dataclass
class SkillRelayPackage:
    """
    Skill Relay 整改包

    包含整改建议和修复结果的状态追踪。
    """
    package_id: str
    finding_id: str
    finding_title: str
    finding_severity: str
    ai_patch_prompt: str
    patch_constraints: Dict[str, Any] = field(default_factory=dict)
    retest_plan: List[Dict[str, Any]] = field(default_factory=list)
    acceptance_criteria: List[str] = field(default_factory=list)

    # 状态追踪
    state: RelayState = RelayState.DRAFT
    events: List[RelayEvent] = field(default_factory=list)
    state_history: List[RelayState] = field(default_factory=list)

    # 修复结果
    fix_result: Optional[Dict[str, Any]] = None
    fix_summary: Optional[str] = None
    fix_commit: Optional[str] = None
    fix_diff: Optional[str] = None
    retest_results: List[Dict[str, Any]] = field(default_factory=list)

    # 元数据
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "package_id": self.package_id,
            "finding_id": self.finding_id,
            "finding_title": self.finding_title,
            "finding_severity": self.finding_severity,
            "ai_patch_prompt": self.ai_patch_prompt,
            "patch_constraints": self.patch_constraints,
            "retest_plan": self.retest_plan,
            "acceptance_criteria": self.acceptance_criteria,
            "state": self.state.value,
            "events": [e.to_dict() for e in self.events],
            "state_history": [s.value for s in self.state_history],
            "fix_result": self.fix_result,
            "fix_summary": self.fix_summary,
            "fix_commit": self.fix_commit,
            "fix_diff": self.fix_diff,
            "retest_results": self.retest_results,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "metadata": self.metadata,
        }


class SkillRelayManager:
    """
    Skill Relay 管理器

    管理整改包在 AI 助手和平台之间的流转。

    Example:
        manager = SkillRelayManager()
        package = manager.create_package(finding, remediation_bundle)
        manager.dispatch(package)
        manager.acknowledge(package, "AI: Starting fix")
        manager.complete(package, {"status": "fixed"})
        result = manager.return_results(package)
    """

    def __init__(self):
        self.packages: Dict[str, SkillRelayPackage] = {}
        self._valid_transitions = self._build_valid_transitions()

    def _build_valid_transitions(self) -> Dict[RelayState, List[RelayState]]:
        """构建有效状态转换图"""
        return {
            RelayState.DRAFT: [RelayState.DISPATCHED, RelayState.REJECTED],
            RelayState.DISPATCHED: [RelayState.ACKNOWLEDGED, RelayState.FAILED],
            RelayState.ACKNOWLEDGED: [RelayState.IN_PROGRESS, RelayState.REJECTED],
            RelayState.IN_PROGRESS: [RelayState.COMPLETED, RelayState.FAILED],
            RelayState.COMPLETED: [RelayState.RETURNED],
            RelayState.RETURNED: [],
            RelayState.REJECTED: [RelayState.DISPATCHED],  # 可以重新分发
            RelayState.FAILED: [RelayState.DISPATCHED],    # 可以重新分发
        }

    def create_package(
        self,
        finding: Dict[str, Any],
        bundle: Dict[str, Any],
    ) -> SkillRelayPackage:
        """
        创建整改包

        Args:
            finding: 漏洞发现
            bundle: 整改包数据

        Returns:
            SkillRelayPackage 实例
        """
        package_id = f"RELAY-{finding.get('id', 'unknown')}"

        package = SkillRelayPackage(
            package_id=package_id,
            finding_id=finding.get("id", ""),
            finding_title=finding.get("title", "Unknown"),
            finding_severity=finding.get("severity", "medium"),
            ai_patch_prompt=bundle.get("ai_patch_prompt", ""),
            patch_constraints={
                c.get("type", "unknown"): c.get("description", "")
                for c in bundle.get("patch_constraints", [])
            },
            retest_plan=bundle.get("retest_plan", []),
            acceptance_criteria=bundle.get("acceptance_criteria", []),
            state=RelayState.DRAFT,
            state_history=[RelayState.DRAFT],
            events=[
                RelayEvent(
                    from_state=RelayState.DRAFT,
                    to_state=RelayState.DRAFT,
                    timestamp=datetime.now(),
                    actor="system",
                    message="整改包创建完成",
                )
            ],
        )

        self.packages[package_id] = package
        logger.info(f"Created relay package: {package_id}")

        return package

    def transition(
        self,
        package: SkillRelayPackage,
        to_state: RelayState,
        actor: str = "system",
        message: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        状态转换

        Args:
            package: 整改包
            to_state: 目标状态
            actor: 执行者
            message: 转换消息
            metadata: 元数据

        Returns:
            是否成功
        """
        allowed_states = self._valid_transitions.get(package.state, [])

        if to_state not in allowed_states:
            logger.warning(
                f"Invalid transition: {package.state.value} -> {to_state.value}"
            )
            return False

        # 记录事件
        event = RelayEvent(
            from_state=package.state,
            to_state=to_state,
            timestamp=datetime.now(),
            actor=actor,
            message=message,
            metadata=metadata or {},
        )

        package.events.append(event)
        package.state_history.append(to_state)
        package.state = to_state
        package.updated_at = datetime.now()

        if to_state == RelayState.COMPLETED:
            package.completed_at = datetime.now()

        logger.info(
            f"Package {package.package_id}: {event.from_state.value} -> {event.to_state.value}"
        )

        return True

    def dispatch(self, package: SkillRelayPackage) -> bool:
        """分发整改包给 AI 助手"""
        return self.transition(
            package,
            RelayState.DISPATCHED,
            actor="system",
            message="整改包已分发至 AI 助手",
        )

    def acknowledge(self, package: SkillRelayPackage, message: str = "") -> bool:
        """AI 助手确认接收整改包"""
        return self.transition(
            package,
            RelayState.ACKNOWLEDGED,
            actor="ai_assistant",
            message=message or "AI 助手已接收整改包",
        )

    def start_fix(self, package: SkillRelayPackage, message: str = "") -> bool:
        """AI 助手开始修复"""
        return self.transition(
            package,
            RelayState.IN_PROGRESS,
            actor="ai_assistant",
            message=message or "AI 助手开始修复",
        )

    def complete_fix(
        self,
        package: SkillRelayPackage,
        result: Dict[str, Any],
        summary: str = "",
        commit: Optional[str] = None,
        diff: Optional[str] = None,
    ) -> bool:
        """AI 助手完成修复"""
        package.fix_result = result
        package.fix_summary = summary
        package.fix_commit = commit
        package.fix_diff = diff

        return self.transition(
            package,
            RelayState.COMPLETED,
            actor="ai_assistant",
            message=summary or "AI 助手完成修复",
        )

    def return_results(
        self,
        package: SkillRelayPackage,
        retest_results: Optional[List[Dict[str, Any]]] = None,
    ) -> bool:
        """返回修复结果给平台"""
        if retest_results:
            package.retest_results = retest_results

        return self.transition(
            package,
            RelayState.RETURNED,
            actor="system",
            message="修复结果已返回平台",
        )

    def reject(self, package: SkillRelayPackage, reason: str = "") -> bool:
        """拒绝修复"""
        return self.transition(
            package,
            RelayState.REJECTED,
            actor="ai_assistant",
            message=reason or "无法修复",
        )

    def fail(self, package: SkillRelayPackage, error: str = "") -> bool:
        """修复失败"""
        return self.transition(
            package,
            RelayState.FAILED,
            actor="system",
            message=error or "修复失败",
        )

    def get_package(self, package_id: str) -> Optional[SkillRelayPackage]:
        """获取整改包"""
        return self.packages.get(package_id)

    def get_all_packages(self) -> List[SkillRelayPackage]:
        """获取所有整改包"""
        return list(self.packages.values())

    def get_packages_by_state(self, state: RelayState) -> List[SkillRelayPackage]:
        """按状态获取整改包"""
        return [p for p in self.packages.values() if p.state == state]

    def get_pending_packages(self) -> List[SkillRelayPackage]:
        """获取待处理的整改包"""
        return self.get_packages_by_state(RelayState.DISPATCHED)

    def get_completed_packages(self) -> List[SkillRelayPackage]:
        """获取已完成的整改包"""
        return self.get_packages_by_state(RelayState.RETURNED)

    def get_summary(self) -> Dict[str, Any]:
        """获取状态摘要"""
        state_counts = {}
        for package in self.packages.values():
            state = package.state.value
            state_counts[state] = state_counts.get(state, 0) + 1

        return {
            "total_packages": len(self.packages),
            "state_distribution": state_counts,
            "pending_count": len(self.get_pending_packages()),
            "completed_count": len(self.get_completed_packages()),
        }