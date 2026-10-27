"""
Vibe Sec Platform — ReasoningGuard 推理监护

防止 Agent 推理偏差的监护机制。
借鉴 lz-secure 的 reasoning_monitor.py 设计。

检测的异常推理模式：
1. unsupported_confirmation: 证据不足却试图确认漏洞
2. evidence_mismatch: 证据与结论不匹配
3. reward_hacking_risk: 奖励黑客式自动推进（为了完成数量而降低质量）
4. closure_state_conflict: 闭环状态与监护信号冲突
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    """异常类型"""
    UNSUPPORTED_CONFIRMATION = "unsupported_confirmation"
    EVIDENCE_MISMATCH = "evidence_mismatch"
    REWARD_HACKING_RISK = "reward_hacking_risk"
    CLOSURE_STATE_CONFLICT = "closure_state_conflict"
    PREMATURE_FINALIZATION = "premature_finalization"
    INSUFFICIENT_CONTEXT = "insufficient_context"
    LOGICAL_INCONSISTENCY = "logical_inconsistency"


class VerificationLane(Enum):
    """验证车道"""
    AUTO_VALIDATE = "auto_validate"        # 自动验证
    CALIBRATION_ONLY = "calibration_only"  # 仅校准
    MANUAL_REVIEW = "manual_review"        # 人工审查
    REJECTED = "rejected"                  # 拒绝


@dataclass
class MonitoringResult:
    """监护结果"""
    status: str  # "ready", "blocked", "warning"
    anomalies: list[AnomalyType]
    lane: VerificationLane
    confidence_score: float
    details: dict[str, Any]


class ReasoningGuard:
    """
    推理监护器

    监控 Agent 的推理过程，检测异常推理模式。

    Example:
        guard = ReasoningGuard()

        result = guard.monitor(
            finding={
                "confidence": 0.4,
                "verdict": "confirmed",
                "evidence": [],
            },
            evidence={"items": []},
            context={"phase": "evidence_collection"},
        )

        if result.status == "blocked":
            # 阻止当前操作
            print(f"Blocked: {result.anomalies}")
        elif result.status == "warning":
            # 记录警告
            print(f"Warning: {result.anomalies}")
    """

    # 阻止异常（需要立即阻止）
    BLOCKING_ANOMALIES = {
        AnomalyType.UNSUPPORTED_CONFIRMATION,
        AnomalyType.REWARD_HACKING_RISK,
        AnomalyType.CLOSURE_STATE_CONFLICT,
    }

    # 警告异常（记录但不阻止）
    WARNING_ANOMALIES = {
        AnomalyType.EVIDENCE_MISMATCH,
        AnomalyType.PREMATURE_FINALIZATION,
        AnomalyType.INSUFFICIENT_CONTEXT,
        AnomalyType.LOGICAL_INCONSISTENCY,
    }

    def __init__(
        self,
        *,
        min_confidence_for_confirmation: float = 0.7,
        min_evidence_count: int = 2,
        max_findings_per_session: int = 50,
        enable_reward_hacking_detection: bool = True,
    ):
        self.min_confidence_for_confirmation = min_confidence_for_confirmation
        self.min_evidence_count = min_evidence_count
        self.max_findings_per_session = max_findings_per_session
        self.enable_reward_hacking_detection = enable_reward_hacking_detection

        # 会话统计
        self.session_findings_count = 0
        self.session_confirmations = 0

    def monitor(
        self,
        finding: dict[str, Any],
        evidence: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> MonitoringResult:
        """
        监控推理过程

        Args:
            finding: 漏洞发现数据
            evidence: 证据数据
            context: 上下文数据

        Returns:
            MonitoringResult
        """
        evidence = evidence or {}
        context = context or {}

        anomalies = []

        # 1. 检测 unsupported_confirmation
        if self._check_unsupported_confirmation(finding, evidence):
            anomalies.append(AnomalyType.UNSUPPORTED_CONFIRMATION)

        # 2. 检测 evidence_mismatch
        if self._check_evidence_mismatch(finding, evidence):
            anomalies.append(AnomalyType.EVIDENCE_MISMATCH)

        # 3. 检测 reward_hacking_risk
        if self.enable_reward_hacking_detection and self._check_reward_hacking(finding, context):
            anomalies.append(AnomalyType.REWARD_HACKING_RISK)

        # 4. 检测 closure_state_conflict
        if self._check_closure_state_conflict(finding, context):
            anomalies.append(AnomalyType.CLOSURE_STATE_CONFLICT)

        # 5. 检测 premature_finalization
        if self._check_premature_finalization(finding, evidence):
            anomalies.append(AnomalyType.PREMATURE_FINALIZATION)

        # 6. 检测 insufficient_context
        if self._check_insufficient_context(finding, context):
            anomalies.append(AnomalyType.INSUFFICIENT_CONTEXT)

        # 7. 检测 logical_inconsistency
        if self._check_logical_inconsistency(finding):
            anomalies.append(AnomalyType.LOGICAL_INCONSISTENCY)

        # 确定状态和车道
        blocking_anomalies = set(anomalies) & self.BLOCKING_ANOMALIES
        warning_anomalies = set(anomalies) & self.WARNING_ANOMALIES

        if blocking_anomalies:
            status = "blocked"
        elif warning_anomalies:
            status = "warning"
        else:
            status = "ready"

        lane = self._route_lane(anomalies)
        confidence_score = self._calculate_confidence_score(finding, evidence, anomalies)

        # 更新会话统计
        if "confirmed" in finding.get("verdict", "").lower():
            self.session_confirmations += 1
        self.session_findings_count += 1

        return MonitoringResult(
            status=status,
            anomalies=anomalies,
            lane=lane,
            confidence_score=confidence_score,
            details={
                "finding_id": finding.get("id"),
                "verdict": finding.get("verdict"),
                "confidence": finding.get("confidence"),
                "evidence_count": len(evidence.get("items", [])),
            },
        )

    def _check_unsupported_confirmation(
        self,
        finding: dict[str, Any],
        evidence: dict[str, Any],
    ) -> bool:
        """检测证据不足却试图确认"""
        confidence = float(finding.get("confidence", 0))
        verdict = finding.get("verdict", "").lower()
        evidence_items = evidence.get("items", [])

        # 置信度低但声称确认
        if confidence < self.min_confidence_for_confirmation and "confirmed" in verdict:
            return True

        # 证据不足但声称确认
        if len(evidence_items) < self.min_evidence_count and "confirmed" in verdict:
            return True

        return False

    def _check_evidence_mismatch(
        self,
        finding: dict[str, Any],
        evidence: dict[str, Any],
    ) -> bool:
        """检测证据与结论不匹配"""
        vuln_type = finding.get("vulnerability_type", "")
        evidence_items = evidence.get("items", [])

        # 检查证据类型是否匹配漏洞类型
        for item in evidence_items:
            evidence_type = item.get("type", "")
            if vuln_type and evidence_type:
                # 简单的类型匹配检查
                if vuln_type in ["sql_injection", "command_injection"] and evidence_type == "xss_evidence":
                    return True
                if vuln_type in ["xss"] and evidence_type == "sql_evidence":
                    return True

        return False

    def _check_reward_hacking(
        self,
        finding: dict[str, Any],
        context: dict[str, Any],
    ) -> bool:
        """检测奖励黑客风险"""
        # 检查是否在短时间内产生了过多 findings
        if self.session_findings_count >= self.max_findings_per_session:
            return True

        # 检查确认率是否异常高
        if self.session_findings_count > 10:
            confirmation_rate = self.session_confirmations / self.session_findings_count
            if confirmation_rate > 0.9:  # 确认率超过 90%
                return True

        return False

    def _check_closure_state_conflict(
        self,
        finding: dict[str, Any],
        context: dict[str, Any],
    ) -> bool:
        """检测闭环状态冲突"""
        phase = context.get("phase", "")
        verdict = finding.get("verdict", "").lower()

        # 在证据收集阶段就试图关闭
        if phase == "evidence_collection" and "confirmed" in verdict:
            return True

        return False

    def _check_premature_finalization(
        self,
        finding: dict[str, Any],
        evidence: dict[str, Any],
    ) -> bool:
        """检测过早最终化"""
        evidence_items = evidence.get("items", [])
        verdict = finding.get("verdict", "").lower()

        # 证据不足但试图最终化
        if len(evidence_items) < 1 and "finalized" in verdict:
            return True

        return False

    def _check_insufficient_context(
        self,
        finding: dict[str, Any],
        context: dict[str, Any],
    ) -> bool:
        """检测上下文不足"""
        # 检查是否有必要的上下文信息
        required_context = ["phase", "project_path"]
        missing = [key for key in required_context if key not in context]

        if len(missing) >= 2:
            return True

        return False

    def _check_logical_inconsistency(self, finding: dict[str, Any]) -> bool:
        """检测逻辑不一致"""
        severity = finding.get("severity", "").lower()
        confidence = float(finding.get("confidence", 0))

        # 低置信度但高严重性
        if confidence < 0.5 and severity in ["critical", "high"]:
            return True

        return False

    def _route_lane(self, anomalies: list[AnomalyType]) -> VerificationLane:
        """路由到验证车道"""
        if AnomalyType.REWARD_HACKING_RISK in anomalies:
            return VerificationLane.MANUAL_REVIEW
        if AnomalyType.UNSUPPORTED_CONFIRMATION in anomalies:
            return VerificationLane.CALIBRATION_ONLY
        if AnomalyType.CLOSURE_STATE_CONFLICT in anomalies:
            return VerificationLane.MANUAL_REVIEW
        if anomalies:
            return VerificationLane.AUTO_VALIDATE
        return VerificationLane.AUTO_VALIDATE

    def _calculate_confidence_score(
        self,
        finding: dict[str, Any],
        evidence: dict[str, Any],
        anomalies: list[AnomalyType],
    ) -> float:
        """计算置信度分数"""
        base_confidence = float(finding.get("confidence", 0.5))

        # 根据证据数量调整
        evidence_count = len(evidence.get("items", []))
        evidence_factor = min(evidence_count / self.min_evidence_count, 1.0)

        # 根据异常数量惩罚
        anomaly_penalty = len(anomalies) * 0.1

        score = base_confidence * evidence_factor * (1.0 - anomaly_penalty)
        return max(0.0, min(1.0, score))

    def reset_session(self) -> None:
        """重置会话统计"""
        self.session_findings_count = 0
        self.session_confirmations = 0

    def get_session_stats(self) -> dict[str, Any]:
        """获取会话统计"""
        return {
            "findings_count": self.session_findings_count,
            "confirmations_count": self.session_confirmations,
            "confirmation_rate": (
                self.session_confirmations / self.session_findings_count
                if self.session_findings_count > 0
                else 0.0
            ),
        }
