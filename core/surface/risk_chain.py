"""
Vibe Sec Platform — RiskChain 风险链分析

将孤立的 finding 串联为完整的攻击路径：
- source_signal: 攻击入口（用户输入、外部数据）
- preconditions: 前置条件（认证状态、环境条件）
- boundary_path: 边界穿越路径（从入口到目标）
- impact_hypothesis: 影响假设（可能的危害）
- evidence_predicates: 证据谓词（支持证据）
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ImpactType(Enum):
    """影响类型"""
    DATA_BREACH = "data_breach"              # 数据泄露
    PRIVILEGE_ESCALATION = "privilege_escalation"  # 权限提升
    REMOTE_CODE_EXECUTION = "remote_code_execution"  # 远程代码执行
    DENIAL_OF_SERVICE = "denial_of_service"  # 拒绝服务
    INFORMATION_DISCLOSURE = "information_disclosure"  # 信息泄露
    AUTHENTICATION_BYPASS = "authentication_bypass"  # 认证绕过


@dataclass
class SourceSignal:
    """攻击入口信号"""
    type: str  # "user_input", "external_data", "file_upload", etc.
    location: str  # 入口位置（文件:行号）
    data_type: str  # 数据类型
    validation_status: str = "unknown"  # "validated", "unvalidated", "partially_validated"
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "location": self.location,
            "data_type": self.data_type,
            "validation_status": self.validation_status,
            "description": self.description,
        }


@dataclass
class Precondition:
    """前置条件"""
    type: str  # "authentication", "authorization", "environment", "state"
    description: str
    required: bool = True
    current_status: str = "unknown"  # "met", "not_met", "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "description": self.description,
            "required": self.required,
            "current_status": self.current_status,
        }


@dataclass
class BoundaryCrossing:
    """边界穿越"""
    from_zone: str  # 来源区域
    to_zone: str  # 目标区域
    boundary_type: str  # 边界类型
    validation_mechanism: Optional[str] = None  # 验证机制
    bypass_possible: bool = False  # 是否可能绕过
    boundary_status: str = "observed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_zone": self.from_zone,
            "to_zone": self.to_zone,
            "boundary_type": getattr(self.boundary_type, "value", self.boundary_type),
            "validation_mechanism": self.validation_mechanism,
            "bypass_possible": self.bypass_possible,
            "boundary_status": self.boundary_status,
        }


@dataclass
class ImpactHypothesis:
    """影响假设"""
    impact_type: ImpactType
    description: str
    severity: str = "medium"  # low, medium, high, critical
    confidence: float = 0.5
    affected_assets: List[str] = field(default_factory=list)
    exploitation_complexity: str = "medium"  # low, medium, high

    def to_dict(self) -> Dict[str, Any]:
        return {
            "impact_type": self.impact_type.value,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "affected_assets": self.affected_assets,
            "exploitation_complexity": self.exploitation_complexity,
        }


@dataclass
class EvidencePredicate:
    """证据谓词"""
    predicate_type: str  # "code_pattern", "data_flow", "configuration", "runtime_behavior"
    description: str
    evidence_location: str  # 证据位置
    strength: float = 0.5  # 证据强度 0.0-1.0
    supports: bool = True  # True: 支持漏洞存在, False: 反驳漏洞存在

    def to_dict(self) -> Dict[str, Any]:
        return {
            "predicate_type": self.predicate_type,
            "description": self.description,
            "evidence_location": self.evidence_location,
            "strength": self.strength,
            "supports": self.supports,
        }


@dataclass
class RiskChain:
    """
    风险链

    将孤立的 finding 串联为完整的攻击路径。
    """
    finding_id: str
    vulnerability_type: str
    source_signal: SourceSignal
    preconditions: List[Precondition] = field(default_factory=list)
    boundary_path: List[BoundaryCrossing] = field(default_factory=list)
    boundary_gap: bool = False
    impact_hypothesis: ImpactHypothesis = None
    evidence_predicates: List[EvidencePredicate] = field(default_factory=list)

    # 元数据
    overall_confidence: float = 0.5
    exploitability: str = "medium"  # low, medium, high
    description: Optional[str] = None

    def __post_init__(self):
        if self.impact_hypothesis is None:
            self.impact_hypothesis = ImpactHypothesis(
                impact_type=ImpactType.INFORMATION_DISCLOSURE,
                description="Unknown impact",
            )

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "finding_id": self.finding_id,
            "vulnerability_type": self.vulnerability_type,
            "source_signal": self.source_signal.to_dict(),
            "preconditions": [p.to_dict() for p in self.preconditions],
            "boundary_path": [b.to_dict() for b in self.boundary_path],
            "boundary_gap": self.boundary_gap,
            "impact_hypothesis": self.impact_hypothesis.to_dict(),
            "evidence_predicates": [e.to_dict() for e in self.evidence_predicates],
            "overall_confidence": self.overall_confidence,
            "exploitability": self.exploitability,
            "description": self.description,
        }

    def calculate_confidence(self) -> float:
        """计算整体置信度"""
        # 基于证据强度计算置信度
        if not self.evidence_predicates:
            return 0.3

        supporting_evidence = [e for e in self.evidence_predicates if e.supports]
        if not supporting_evidence:
            return 0.2

        # 平均证据强度
        avg_strength = sum(e.strength for e in supporting_evidence) / len(supporting_evidence)

        # 考虑前置条件和边界穿越
        precondition_factor = 1.0
        if self.preconditions:
            met_preconditions = [p for p in self.preconditions if p.current_status == "met"]
            if met_preconditions:
                precondition_factor = 0.8  # 前置条件已满足，增加可能性
            else:
                precondition_factor = 0.6  # 前置条件未满足，降低可能性

        boundary_factor = 1.0
        if self.boundary_path:
            bypassable_boundaries = [b for b in self.boundary_path if b.bypass_possible]
            if bypassable_boundaries:
                boundary_factor = 1.2  # 存在可绕过的边界，增加可能性
            else:
                boundary_factor = 0.7  # 边界验证有效，降低可能性

        confidence = avg_strength * precondition_factor * boundary_factor
        return min(max(confidence, 0.0), 1.0)

    def assess_exploitability(self) -> str:
        """评估可利用性"""
        # 基于多个因素评估可利用性
        score = 0

        # 前置条件
        if not self.preconditions or all(p.current_status == "met" for p in self.preconditions):
            score += 2
        elif any(p.current_status == "met" for p in self.preconditions):
            score += 1

        # 边界穿越
        if any(b.bypass_possible for b in self.boundary_path):
            score += 2

        # 证据强度
        if self.evidence_predicates:
            avg_strength = sum(e.strength for e in self.evidence_predicates if e.supports) / len(
                [e for e in self.evidence_predicates if e.supports]
            )
            if avg_strength >= 0.7:
                score += 2
            elif avg_strength >= 0.5:
                score += 1

        # 评估结果
        if score >= 5:
            return "high"
        elif score >= 3:
            return "medium"
        else:
            return "low"


class RiskChainBuilder:
    """
    RiskChain 构建器

    从 finding 和 RuntimeSurface 构建风险链。
    """

    def __init__(self, runtime_surface):
        self.runtime_surface = runtime_surface

    def build_risk_chains(self, findings: List[Dict[str, Any]]) -> List[RiskChain]:
        """
        构建风险链

        Args:
            findings: 漏洞发现列表

        Returns:
            RiskChain 列表
        """
        logger.info(f"Building risk chains for {len(findings)} findings")

        risk_chains = []

        for finding in findings:
            try:
                chain = self._build_single_chain(finding)
                if chain:
                    # 计算置信度和可利用性
                    chain.overall_confidence = chain.calculate_confidence()
                    chain.exploitability = chain.assess_exploitability()

                    risk_chains.append(chain)
            except Exception as e:
                logger.warning(f"Failed to build risk chain for {finding.get('id')}: {e}")
                continue

        logger.info(f"Built {len(risk_chains)} risk chains")

        return risk_chains

    def _build_single_chain(self, finding: Dict[str, Any]) -> Optional[RiskChain]:
        """构建单个风险链"""
        finding_id = finding.get("id", "unknown")
        vuln_type = finding.get("vulnerability_type", "unknown")
        file_path = finding.get("file_path", "")
        line_start = finding.get("line_start", 0)

        # 1. 识别攻击入口
        source_signal = self._identify_source_signal(finding)

        # 2. 识别前置条件
        preconditions = self._identify_preconditions(finding)

        # 3. 构建边界穿越路径
        boundary_path = self._build_boundary_path(finding)

        # 4. 评估影响
        impact_hypothesis = self._assess_impact(finding)

        # 5. 收集证据
        evidence_predicates = self._collect_evidence(finding)

        # 6. 创建风险链
        chain = RiskChain(
            finding_id=finding_id,
            vulnerability_type=vuln_type,
            source_signal=source_signal,
            preconditions=preconditions,
            boundary_path=boundary_path,
            boundary_gap=not boundary_path,
            impact_hypothesis=impact_hypothesis,
            evidence_predicates=evidence_predicates,
            description=f"Risk chain for {vuln_type} at {file_path}:{line_start}",
        )

        return chain

    def _identify_source_signal(self, finding: Dict[str, Any]) -> SourceSignal:
        """识别攻击入口"""
        vuln_type = finding.get("vulnerability_type", "")
        file_path = finding.get("file_path", "")
        line_start = finding.get("line_start", 0)

        # 根据漏洞类型推断入口信号
        if vuln_type in ["sql_injection", "command_injection", "xss", "path_traversal"]:
            return SourceSignal(
                type="user_input",
                location=f"{file_path}:{line_start}",
                data_type="string",
                validation_status="unvalidated",
                description="User input without proper validation",
            )
        elif vuln_type in ["hardcoded_password", "api_key"]:
            return SourceSignal(
                type="configuration",
                location=f"{file_path}:{line_start}",
                data_type="credential",
                validation_status="unknown",
                description="Hardcoded credential in source code",
            )
        elif vuln_type in ["prompt_injection"]:
            return SourceSignal(
                type="external_data",
                location=f"{file_path}:{line_start}",
                data_type="text",
                validation_status="unvalidated",
                description="External text data without sanitization",
            )
        else:
            return SourceSignal(
                type="unknown",
                location=f"{file_path}:{line_start}",
                data_type="unknown",
                validation_status="unknown",
            )

    def _identify_preconditions(self, finding: Dict[str, Any]) -> List[Precondition]:
        """识别前置条件"""
        preconditions = []

        # 检查是否有认证要求
        file_path = finding.get("file_path", "")
        # 查找相关的权限配置
        for perm in self.runtime_surface.permission_profiles:
            if perm.file_path == file_path:
                preconditions.append(Precondition(
                    type=perm.permission_type,
                    description=f"{perm.permission_type} check at {perm.file_path}:{perm.line_start}",
                    required=True,
                    current_status="unknown",
                ))

        # 如果没有找到权限配置，假设不需要认证
        if not preconditions:
            preconditions.append(Precondition(
                type="authentication",
                description="No authentication required",
                required=False,
                current_status="met",
            ))

        return preconditions

    def _build_boundary_path(self, finding: Dict[str, Any]) -> List[BoundaryCrossing]:
        """构建边界穿越路径"""
        boundary_path = []

        # 查找相关的信任边界
        for boundary in self.runtime_surface.trust_boundaries:
            if boundary.file_path == finding.get("file_path"):
                boundary_path.append(BoundaryCrossing(
                    from_zone=boundary.source,
                    to_zone=boundary.target,
                    boundary_type=boundary.boundary_type,
                    validation_mechanism=boundary.validation_mechanism,
                    bypass_possible=not boundary.validation_mechanism,
                    boundary_status="observed",
                ))

        # 如果没有找到边界，创建一个默认边界
        return boundary_path

    def _assess_impact(self, finding: Dict[str, Any]) -> ImpactHypothesis:
        """评估影响"""
        vuln_type = finding.get("vulnerability_type", "")
        severity = finding.get("severity", "medium")

        # 根据漏洞类型映射影响类型
        impact_mapping = {
            "sql_injection": (ImpactType.DATA_BREACH, "Database data exposure"),
            "command_injection": (ImpactType.REMOTE_CODE_EXECUTION, "Arbitrary code execution"),
            "xss": (ImpactType.INFORMATION_DISCLOSURE, "Session hijacking, data theft"),
            "path_traversal": (ImpactType.DATA_BREACH, "Unauthorized file access"),
            "hardcoded_password": (ImpactType.AUTHENTICATION_BYPASS, "Credential compromise"),
            "api_key": (ImpactType.DATA_BREACH, "API abuse, data exposure"),
            "prompt_injection": (ImpactType.PRIVILEGE_ESCALATION, "Agent manipulation"),
        }

        impact_type, description = impact_mapping.get(
            vuln_type,
            (ImpactType.INFORMATION_DISCLOSURE, "Unknown impact"),
        )

        return ImpactHypothesis(
            impact_type=impact_type,
            description=description,
            severity=severity,
            confidence=0.7,
            affected_assets=["application", "data"],
            exploitation_complexity="medium",
        )

    def _collect_evidence(self, finding: Dict[str, Any]) -> List[EvidencePredicate]:
        """收集证据"""
        evidence_predicates = []

        # 代码模式证据
        evidence = finding.get("evidence", [])
        for ev in evidence:
            if ev.get("type") == "code_snippet":
                evidence_predicates.append(EvidencePredicate(
                    predicate_type="code_pattern",
                    description="Vulnerable code pattern found",
                    evidence_location=f"{finding.get('file_path')}:{finding.get('line_start')}",
                    strength=0.7,
                    supports=True,
                ))
            elif ev.get("type") == "llm_analysis":
                evidence_predicates.append(EvidencePredicate(
                    predicate_type="ai_analysis",
                    description=ev.get("explanation", "LLM analysis"),
                    evidence_location="ai_assessment",
                    strength=0.6,
                    supports=True,
                ))

        # 如果没有证据，添加一个弱证据
        if not evidence_predicates:
            evidence_predicates.append(EvidencePredicate(
                predicate_type="pattern_match",
                description="Pattern-based detection",
                evidence_location=f"{finding.get('file_path')}:{finding.get('line_start')}",
                strength=0.4,
                supports=True,
            ))

        return evidence_predicates
