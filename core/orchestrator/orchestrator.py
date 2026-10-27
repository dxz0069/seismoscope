"""
Vibe Sec Platform — 确定性编排器

实现固定的审查流程编排，不让 LLM 决定主要阶段。
借鉴 AutoCVE 的 orchestrator.py 设计，但简化为更清晰的阶段划分。

编排流程：
1. Recon（信息收集）
2. Surface（攻击面建模）
3. Audit（漏洞审查，可并行多 Agent）
4. Merge（合并发现）
5. Verification（漏洞验证）
6. Remediation（整改建议）
7. Regression（回归测试，可选）
"""

import asyncio
import logging
import math
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from ..agent_runtime.completion import FinalizeTaskContract
from ..agent_runtime.graph import TaskGraphController
from ..agent_runtime.guard import AgentGuard
from ..agent_runtime.loop import AgentTaskLoop
from ..agent_runtime.task import AgentTask
from ..agents.base import (
    AgentConfig,
    AgentPattern,
    AgentResult,
    AgentType,
    BaseAgent,
    LLMService,
    TaskHandoff,
)
from ..agents.registry import AgentRegistry, AgentState
from ..audit.finding_cluster import cluster_findings
from ..audit.lanes import group_findings_by_lane
from ..audit.models import normalize_finding
from ..audit.suppression import apply_suppressions
from ..harness.models import ProjectProfile, RuntimeSurfaceGraph
from ..harness.return_protocol import build_return_packages
from ..policy.closure_policy import ClosurePolicy
from ..reasoning.reasoning_guard import ReasoningGuard
from ..session.models import RunSession, RunStatus
from ..session.store import SessionStore
from ..surface.threat_model import RuntimeThreatModelAnalyzer
from ..vrtm.lifecycle import analyze_graph_changes, bind_hypothesis_statuses, compare_threat_models
from ..vrtm.observations import observations_from_audit, observations_from_verification

logger = logging.getLogger(__name__)


class OrchestrationPhase(Enum):
    """编排阶段枚举"""
    INIT = "init"
    PLAN = "plan"
    RECON = "recon"
    SURFACE = "surface"
    AUDIT = "audit"
    MERGE = "merge"
    VERIFICATION = "verification"
    REMEDIATION = "remediation"
    RETURN = "return"
    REGRESSION = "regression"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class OrchestrationConfig:
    """编排器配置"""
    enable_recon: bool = True
    enable_surface: bool = True
    enable_audit: bool = True
    enable_verification: bool = True
    enable_remediation: bool = True
    enable_return: bool = True
    enable_regression: bool = False  # 默认关闭，可选

    # 并行审计配置
    parallel_audit: bool = True  # 是否并行执行多个审计 Agent
    parallel_audit_lanes: bool = True
    audit_concurrency: int = 3

    # 验证配置
    verification_threshold: float = 0.6  # 只有置信度 >= 此值的 finding 才会验证
    max_verification_count: int = 20  # Small-project verification floor.
    verification_fraction: float = 0.30
    verification_sample_per_type: int = 3

    # 超时配置
    phase_timeout_seconds: int = 600  # 每个阶段的超时时间
    enable_agent_runtime: bool = True
    enable_react_audit: bool = True
    enable_react_verification: bool = True
    agent_max_attempts: int = 3
    agent_max_turns: int = 20
    agent_loop_repeat_limit: int = 3
    parallel_verification: bool = True
    verification_concurrency: int = 4


@dataclass
class OrchestrationState:
    """编排状态"""
    current_phase: OrchestrationPhase = OrchestrationPhase.INIT
    phase_results: dict[OrchestrationPhase, AgentResult] = field(default_factory=dict)
    phase_handoffs: dict[OrchestrationPhase, TaskHandoff] = field(default_factory=dict)

    # 合并后的 findings
    merged_findings: list[dict[str, Any]] = field(default_factory=list)
    # Scanner/lane output remains available for auditability.  ``merged_findings``
    # is only the smaller, traceable review projection.
    raw_findings: list[dict[str, Any]] = field(default_factory=list)

    # 验证后的 findings
    verified_findings: list[dict[str, Any]] = field(default_factory=list)
    rejected_findings: list[dict[str, Any]] = field(default_factory=list)
    needs_evidence_findings: list[dict[str, Any]] = field(default_factory=list)
    not_reviewed_findings: list[dict[str, Any]] = field(default_factory=list)

    # 整改包
    remediation_bundles: list[dict[str, Any]] = field(default_factory=list)

    # 回归测试报告
    regression_reports: list[dict[str, Any]] = field(default_factory=list)

    # 错误信息
    error: str | None = None
    session: RunSession | None = None
    project_profile: dict[str, Any] = field(default_factory=dict)
    runtime_surface_graph: dict[str, Any] = field(default_factory=dict)
    runtime_threat_model: dict[str, Any] = field(default_factory=dict)
    runtime_graph_observations: list[dict[str, Any]] = field(default_factory=list)
    vrtm_evolution: list[dict[str, Any]] = field(default_factory=list)
    lane_findings: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    returned_packages: list[dict[str, Any]] = field(default_factory=list)
    audit_request: dict[str, Any] = field(default_factory=dict)


class OrchestratorAgent(BaseAgent):
    """
    确定性编排器

    强制执行固定的审查流程，协调多个子 Agent 完成任务。
    不允许 LLM 自行决定主要阶段。

    Example:
        orchestrator = OrchestratorAgent(
            llm_service=llm_service,
            agent_registry=registry,
            config=OrchestrationConfig(),
        )

        result = await orchestrator.run({
            "project_path": "/path/to/project",
            "audit_scope": {"web_vulns": True, "agent_vulns": True},
        })
    """

    def __init__(
        self,
        llm_service: LLMService,
        agent_registry: AgentRegistry,
        config: OrchestrationConfig | None = None,
        event_emitter: Callable | None = None,
        session_store: SessionStore | None = None,
    ):
        super().__init__(
            config=AgentConfig(
                name="Orchestrator",
                agent_type=AgentType.ORCHESTRATOR,
                pattern=AgentPattern.PLAN_AND_EXECUTE,
                max_iterations=10,
            ),
            llm_service=llm_service,
            event_emitter=event_emitter,
        )

        self.agent_registry = agent_registry
        self.orch_config = config or OrchestrationConfig()
        self.session_store = session_store
        self.state = OrchestrationState()

    def _record_event(
        self,
        event_type: str,
        phase: OrchestrationPhase,
        message: str = "",
        data: dict[str, Any] | None = None,
    ) -> None:
        if self.state.session:
            self.state.session.emit(event_type, phase.value, message, data or {})

    async def run(self, payload: dict[str, Any]) -> AgentResult:
        """
        执行确定性编排流程

        Args:
            payload: 输入数据，包含：
                - project_path: 项目路径
                - audit_scope: 审计范围配置
                - 其他可选参数

        Returns:
            AgentResult 包含完整的审查结果
        """
        logger.info("Starting orchestration")
        self.state = OrchestrationState()
        self.state.session = RunSession(
            project_path=payload.get("project_path", ""),
            trigger=payload.get("trigger", "explicit"),
            metadata=dict(payload.get("session_metadata") or {}),
        )
        self.state.session.start()
        payload = {**payload, "session_id": self.state.session.session_id}
        self.state.audit_request = {
            "trigger": payload.get("trigger", "explicit"),
            "changed_files": list(payload.get("changed_files", []) or []),
            "scope": dict(payload.get("audit_scope", {}) or {}),
        }
        if payload.get("allow_dependency_network", False):
            self.state.audit_request["allow_dependency_network"] = True

        try:
            self.state.current_phase = OrchestrationPhase.PLAN
            self._record_event("phase_started", OrchestrationPhase.PLAN, "Audit plan created")
            self.state.session.checkpoint(
                OrchestrationPhase.PLAN.value,
                {
                    "audit_scope": payload.get("audit_scope", {}),
                    "project_path": payload.get("project_path", ""),
                    "trigger": payload.get("trigger", "explicit"),
                    "changed_files": list(payload.get("changed_files", []) or []),
                    "allow_dependency_network": bool(payload.get("allow_dependency_network", False)),
                },
            )
            self.state.session.phases_completed.append(OrchestrationPhase.PLAN.value)
            self._record_event("phase_completed", OrchestrationPhase.PLAN, "Audit plan accepted")
            # 阶段 1: Recon 信息收集
            if self.orch_config.enable_recon:
                await self._run_phase(
                    OrchestrationPhase.RECON,
                    payload,
                )

            # 阶段 2: Surface 攻击面建模
            if self.orch_config.enable_surface:
                await self._run_phase(
                    OrchestrationPhase.SURFACE,
                    self._build_phase_payload(OrchestrationPhase.SURFACE, payload),
                )

            # 阶段 3: Audit 漏洞审查（可并行）
            if self.orch_config.enable_audit:
                await self._run_audit_phase(
                    self._build_phase_payload(OrchestrationPhase.AUDIT, payload),
                )

            # 阶段 4: Merge 合并发现（内部处理，不运行 Agent）
            await self._run_merge_phase()

            # 阶段 5: Verification 漏洞验证
            if self.orch_config.enable_verification:
                await self._run_phase(
                    OrchestrationPhase.VERIFICATION,
                    self._build_phase_payload(OrchestrationPhase.VERIFICATION, payload),
                )

            # 阶段 6: Remediation 整改建议
            if self.orch_config.enable_remediation:
                await self._run_phase(
                    OrchestrationPhase.REMEDIATION,
                    self._build_phase_payload(OrchestrationPhase.REMEDIATION, payload),
                )

            # 阶段 7: Regression 回归测试（可选）
            if self.orch_config.enable_return:
                self._run_return_phase()

            if self.orch_config.enable_regression:
                await self._run_phase(
                    OrchestrationPhase.REGRESSION,
                    self._build_phase_payload(OrchestrationPhase.REGRESSION, payload),
                )

            self.state.current_phase = OrchestrationPhase.COMPLETED
            self.state.session.phases_completed.append(OrchestrationPhase.COMPLETED.value)
            self.state.session.complete(RunStatus.COMPLETED)

            return self._build_final_result()

        except Exception as e:
            logger.error(f"Orchestration failed: {e}", exc_info=True)
            self.state.current_phase = OrchestrationPhase.FAILED
            self.state.error = str(e)
            if self.state.session:
                self._record_event("run_failed", self.state.current_phase, str(e))
                self.state.session.complete(RunStatus.FAILED)

            return AgentResult.failure_result(
                error=str(e),
                data={
                    "partial_results": self._collect_partial_results(),
                },
            )

    async def _run_phase(
        self,
        phase: OrchestrationPhase,
        payload: dict[str, Any],
    ) -> None:
        """
        运行单个阶段

        Args:
            phase: 阶段类型
            payload: 输入数据
        """
        logger.info(f"Running phase: {phase.value}")

        self.state.current_phase = phase
        self._record_event("phase_started", phase, f"Running {phase.value}")

        # 获取对应的 Agent
        agent_type = self._phase_to_agent_type(phase)
        agent = self.agent_registry.get_instance(agent_type)

        if not agent:
            raise ValueError(f"Agent {agent_type.value} not registered")

        # 检查依赖是否满足
        if not self.agent_registry.check_dependencies_satisfied(agent_type):
            raise ValueError(f"Dependencies not satisfied for {agent_type.value}")

        # 更新状态为运行中
        self.agent_registry.set_state(agent_type, AgentState.RUNNING)

        # 执行 Agent
        try:
            if (
                phase == OrchestrationPhase.VERIFICATION
                and self.orch_config.parallel_verification
                and len(payload.get("findings_to_verify", [])) > 1
            ):
                result = await self._run_verification_fanout(
                    agent_type=agent_type,
                    agent=agent,
                    payload=payload,
                )
            else:
                result = await self._run_agent_task(
                    phase=phase,
                    agent_type=agent_type,
                    agent=agent,
                    payload=payload,
                )

            if not result.success:
                raise ValueError(f"Agent {agent_type.value} failed: {result.metadata.get('error')}")

            # 保存结果
            self.state.phase_results[phase] = result
            if result.handoff:
                self.state.phase_handoffs[phase] = result.handoff

            # 特殊处理：提取整改包和回归报告
            if phase == OrchestrationPhase.REMEDIATION:
                self.state.remediation_bundles = result.data.get("remediation_bundles", [])
            elif phase == OrchestrationPhase.VERIFICATION:
                # 提取验证后的 findings
                self.state.verified_findings = result.data.get("verified_findings", [])
                self.state.rejected_findings = result.data.get("rejected_findings", [])
                self.state.needs_evidence_findings = result.data.get("needs_evidence_findings", [])
                verification_findings = [
                    *self.state.verified_findings,
                    *self.state.rejected_findings,
                    *self.state.needs_evidence_findings,
                ]
                result.data["vrtm_evolution"] = self._enrich_vrtm_from_findings(
                    verification_findings, phase="verification",
                )
            elif phase == OrchestrationPhase.REGRESSION:
                # 提取回归测试报告
                self.state.regression_reports = result.data.get("regression_reports", [])
                self._attach_regression_status()

            if phase == OrchestrationPhase.RECON:
                raw_profile = result.data.get("project_profile", {})
                normalized_profile = ProjectProfile.from_dict(raw_profile).to_dict()
                self.state.project_profile = {**raw_profile, **normalized_profile}
            elif phase == OrchestrationPhase.SURFACE:
                self.state.runtime_surface_graph = result.data.get("runtime_surface_graph", {})
                self.state.runtime_threat_model = result.data.get("threat_model", {})

            # 更新状态为完成
            self.agent_registry.set_state(agent_type, AgentState.COMPLETED)
            if self.state.session:
                self.state.session.phases_completed.append(phase.value)
                self.state.session.checkpoint(
                    phase.value,
                    {"result_keys": list(result.data.keys()), "current_phase": phase.value},
                )
                self._record_event("phase_completed", phase, f"Completed {phase.value}")

            logger.info(f"Phase {phase.value} completed successfully")

        except TimeoutError as err:
            self.agent_registry.set_state(agent_type, AgentState.FAILED)
            raise TimeoutError(f"Phase {phase.value} timed out") from err
        except Exception as e:
            self.agent_registry.set_state(agent_type, AgentState.FAILED)
            self._record_event("phase_failed", phase, str(e))
            raise

    async def _run_audit_phase(self, payload: dict[str, Any]) -> None:
        """Run audit lanes as independent, checkpointed child tasks."""
        logger.info("Running audit phase")

        self.state.current_phase = OrchestrationPhase.AUDIT
        self._record_event("phase_started", OrchestrationPhase.AUDIT, "Running audit lanes")

        agent_type = AgentType.AUDIT
        base_agent = self.agent_registry.get_instance(agent_type)
        if not base_agent:
            raise ValueError(f"Agent {agent_type.value} not registered")
        if not self.agent_registry.check_dependencies_satisfied(agent_type):
            raise ValueError(f"Dependencies not satisfied for {agent_type.value}")

        self.agent_registry.set_state(agent_type, AgentState.RUNNING)
        lane_specs = self._build_audit_lane_specs(payload)
        try:
            if (
                self.orch_config.parallel_audit
                and self.orch_config.parallel_audit_lanes
                and len(lane_specs) > 1
            ):
                result = await self._run_audit_lane_fanout(
                    agent_type=agent_type,
                    base_agent=base_agent,
                    payload=payload,
                    lane_specs=lane_specs,
                )
            elif lane_specs:
                result = await self._run_agent_task(
                    phase=OrchestrationPhase.AUDIT,
                    agent_type=agent_type,
                    agent=base_agent,
                    payload=lane_specs[0]["payload"],
                )
                result.data.setdefault("audit_summary", {})["execution_mode"] = "single_lane"
            else:
                result = AgentResult.success_result(
                    data={
                        "findings": [],
                        "findings_by_lane": {},
                        "audit_summary": {
                            "total_candidates": 0,
                            "confirmed_findings": 0,
                            "rejected_candidates": 0,
                            "execution_mode": "no_lanes_enabled",
                        },
                    }
                )

            if not result.success:
                raise ValueError(result.metadata.get("error", "Audit failed"))
            result.data["vrtm_evolution"] = self._enrich_vrtm_from_findings(
                result.data.get("findings", []), phase="audit",
            )
            self.state.phase_results[OrchestrationPhase.AUDIT] = result
            if result.handoff:
                self.state.phase_handoffs[OrchestrationPhase.AUDIT] = result.handoff
            self.agent_registry.set_state(agent_type, AgentState.COMPLETED)
        except Exception:
            self.agent_registry.set_state(agent_type, AgentState.FAILED)
            self._record_event("phase_failed", OrchestrationPhase.AUDIT, "Audit lanes failed")
            raise

        if self.state.session:
            self.state.session.phases_completed.append(OrchestrationPhase.AUDIT.value)
            self.state.session.checkpoint(
                OrchestrationPhase.AUDIT.value,
                {"result_keys": list(result.data.keys())},
            )
            self._record_event("phase_completed", OrchestrationPhase.AUDIT, "Audit lanes completed")

    def _enrich_vrtm_from_findings(
        self,
        findings: list[dict[str, Any]],
        *,
        phase: str,
    ) -> dict[str, Any]:
        if not findings or not self.state.runtime_surface_graph:
            return {
                "schema": "vibe-sec.vrtm.evolution.v1",
                "phase": phase,
                "status": "no_observations",
                "observation_count": 0,
            }

        previous_graph_data = deepcopy(self.state.runtime_surface_graph)
        previous_threat = deepcopy(self.state.runtime_threat_model)
        graph = RuntimeSurfaceGraph.from_dict(previous_graph_data)
        factory = observations_from_verification if phase == "verification" else observations_from_audit
        run_id = self.state.session.session_id if self.state.session else "orchestrator-run"
        observations, diagnostics = factory(
            findings, graph, previous_threat, run_id=run_id,
        )
        if not observations:
            evolution = {
                "schema": "vibe-sec.vrtm.evolution.v1",
                "phase": phase,
                "status": "no_observations",
                "observation_count": 0,
                "diagnostics": diagnostics,
            }
            self.state.vrtm_evolution.append(evolution)
            return evolution

        application = graph.apply_observations(observations)
        accepted_ids = set(application["accepted_observation_ids"])
        accepted = [item for item in observations if item.get("id") in accepted_ids]
        self.state.runtime_graph_observations.extend(accepted)
        threat_model = RuntimeThreatModelAnalyzer(None, graph).analyze()
        bind_hypothesis_statuses(threat_model, self.state.runtime_graph_observations)
        for assumption in previous_threat.get("assumptions", []):
            if assumption not in threat_model.assumptions:
                threat_model.assumptions.append(assumption)
        graph.metadata["threat_model_version"] = threat_model.version
        graph.metadata["hypothesis_count"] = len(threat_model.hypotheses)
        graph.metadata["fingerprint"] = graph.content_fingerprint()
        threat_data = threat_model.to_dict()
        graph_data = graph.to_dict()
        graph_data["visualization"] = graph.to_visualization(threat_data)
        evolution = {
            "schema": "vibe-sec.vrtm.evolution.v1",
            "phase": phase,
            "status": "updated" if accepted else "rejected",
            "observation_count": len(observations),
            "accepted_observation_count": len(accepted),
            "diagnostics": diagnostics,
            "observation_application": application,
            "graph_diff": graph.diff(RuntimeSurfaceGraph.from_dict(previous_graph_data)),
            "threat_model_diff": compare_threat_models(threat_data, previous_threat),
            "security_change_analysis": analyze_graph_changes(graph_data, previous_graph_data),
        }
        self.state.runtime_surface_graph = graph_data
        self.state.runtime_threat_model = threat_data
        self.state.vrtm_evolution.append(evolution)
        if self.state.session:
            self.state.session.update_metadata(
                vrtm_evolution={
                    "latest_phase": phase,
                    "accepted_observation_count": len(accepted),
                    "risk_hypothesis_count": len(threat_data.get("hypotheses", [])),
                    "security_review_required": bool(
                        evolution["security_change_analysis"].get("requires_security_review", False)
                    ),
                }
            )
            self.state.session.checkpoint(
                "threat_model",
                {
                    "phase": phase,
                    "accepted_observation_count": len(accepted),
                    "risk_hypothesis_count": len(threat_data.get("hypotheses", [])),
                    "security_review_required": bool(
                        evolution["security_change_analysis"].get("requires_security_review", False)
                    ),
                },
            )
            self._record_event(
                "vrtm_evolved",
                self.state.current_phase,
                f"Applied {len(accepted)} graph observations during {phase}",
                {"phase": phase, "accepted": len(accepted), "rejected": len(observations) - len(accepted)},
            )
        return evolution

    def _build_audit_lane_specs(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Build only the lanes explicitly enabled by the audit scope."""
        scope = dict(payload.get("audit_scope") or {})
        enabled = lambda key: bool(scope.get(key, True))
        specs = []

        definitions = (
            ("web_audit", "web_vulns"),
            ("agent_audit", "agent_vulns"),
            ("mcp_audit", "mcp_vulns"),
            ("secrets_audit", "secret_leaks"),
            ("workflow_audit", "workflow_vulns"),
        )
        for lane, scope_key in definitions:
            if not enabled(scope_key):
                continue
            lane_scope = {
                "web_vulns": lane == "web_audit",
                "agent_vulns": lane == "agent_audit",
                "mcp_vulns": lane == "mcp_audit",
                "secret_leaks": lane == "secrets_audit",
                "workflow_vulns": lane == "workflow_audit",
            }
            specs.append(
                {
                    "lane": lane,
                    "payload": {
                        **payload,
                        "audit_scope": lane_scope,
                        "audit_lane": lane,
                    },
                }
            )
        return specs

    async def _run_audit_lane_fanout(
        self,
        *,
        agent_type: AgentType,
        base_agent: BaseAgent,
        payload: dict[str, Any],
        lane_specs: list[dict[str, Any]],
    ) -> AgentResult:
        """Run isolated audit agents concurrently and aggregate their handoff."""
        from core.audit.review_budget import SharedReviewBudget

        parent_task_id = f"audit-{self.state.session.session_id if self.state.session else 'run'}"
        child_results: dict[str, AgentResult] = {}
        raw_review_limit = payload.get("react_review_limit")
        shared_review_budget = (
            SharedReviewBudget(raw_review_limit, expected_lanes=len(lane_specs))
            if raw_review_limit is not None and bool(payload.get("enable_react_review"))
            else None
        )
        registration = self.agent_registry.get_registration(agent_type)
        if not registration:
            raise ValueError(f"Agent {agent_type.value} registration not found")

        def checkpoint_sink(current_task: AgentTask, checkpoint: dict[str, Any]) -> None:
            if self.state.session:
                self.state.session.checkpoint("agent_task:audit", checkpoint)
                if self.session_store:
                    self.session_store.save(self.state.session)

        def transition_sink(transition) -> None:
            self._record_event(
                "agent_state_transition",
                OrchestrationPhase.AUDIT,
                transition.reason,
                transition.to_dict(),
            )

        def loop_factory() -> AgentTaskLoop:
            return AgentTaskLoop(
                max_turns=self.orch_config.agent_max_turns,
                timeout_seconds=self.orch_config.phase_timeout_seconds,
                loop_repeat_limit=self.orch_config.agent_loop_repeat_limit,
                guard=AgentGuard(ReasoningGuard()),
                checkpoint_sink=checkpoint_sink,
                transition_sink=transition_sink,
                require_terminal_action=True,
            )

        graph = TaskGraphController(
            max_concurrency=(
                max(self.orch_config.audit_concurrency, len(lane_specs))
                if shared_review_budget is not None and shared_review_budget.uses_global_selection
                else self.orch_config.audit_concurrency
            ),
            loop_factory=loop_factory,
        )
        child_tasks: list[AgentTask] = []
        for spec in lane_specs:
            lane = spec["lane"]
            lane_payload = {
                **spec["payload"],
                "_react_checkpoint_sink": checkpoint_sink,
                "_react_transition_sink": transition_sink,
            }
            if shared_review_budget is not None:
                lane_payload["_react_review_budget"] = shared_review_budget
            lane_agent = registration.agent_class(
                config=AgentConfig(
                    name=f"{base_agent.config.name}:{lane}",
                    agent_type=agent_type,
                ),
                llm_service=self.llm_service,
                event_emitter=self.event_emitter,
            )
            task = AgentTask(
                agent_name=lane_agent.config.name,
                parent_task_id=parent_task_id,
                phase=OrchestrationPhase.AUDIT.value,
                input_payload={"audit_lane": lane, "audit_scope": lane_payload["audit_scope"]},
                max_attempts=self.orch_config.agent_max_attempts,
                completion_contract=FinalizeTaskContract().to_dict(),
                metadata={"agent_type": agent_type.value, "audit_lane": lane},
            )

            async def handler(
                current_task,
                context,
                *,
                lane=lane,
                lane_agent=lane_agent,
                lane_payload=lane_payload,
            ):
                del current_task, context
                result = await lane_agent.run(lane_payload)
                child_results[lane] = result
                if not result.success:
                    return {
                        "status": "failed",
                        "error": result.metadata.get("error", "audit lane failed"),
                        "retryable": True,
                    }
                summary = result.data.get("audit_summary", {})
                return {
                    "done": True,
                    "terminal_action": "FinalizeTask",
                    "output": {
                        "summary": f"{lane} completed with {summary.get('reportable_findings', 0)} findings",
                        "next_action": "handoff_to_merge",
                    },
                }

            graph.add_task(task, handler, context={"audit_lane": lane})
            child_tasks.append(task)

        if self.state.session:
            self.state.session.checkpoint(
                "agent_task:audit",
                {
                    "reason": "parent_dispatched",
                    "parent_task_id": parent_task_id,
                    "children": [task.to_dict() for task in child_tasks],
                },
            )
            if self.session_store:
                self.session_store.save(self.state.session)

        graph_result = await asyncio.wait_for(
            graph.run(context={"phase": "audit", "project_path": payload.get("project_path", "")}),
            timeout=self.orch_config.phase_timeout_seconds,
        )
        if graph_result.status != "completed":
            failed = ", ".join(f"{key}: {value}" for key, value in graph_result.errors.items())
            raise ValueError(f"Audit lane child tasks failed: {failed}")

        findings: list[dict[str, Any]] = []
        lane_counts: dict[str, int] = {}
        handoff = None
        failed_lanes = [
            spec["lane"]
            for spec in lane_specs
            if not child_results.get(spec["lane"]) or not child_results[spec["lane"]].success
        ]
        if failed_lanes:
            raise ValueError(f"Audit lanes failed: {', '.join(sorted(failed_lanes))}")
        for spec in lane_specs:
            lane = spec["lane"]
            result = child_results.get(lane)
            if not result:
                raise ValueError(f"Audit lane {lane} returned no result")
            handoff = handoff or result.handoff
            lane_findings = deepcopy(result.data.get("findings", []))
            lane_counts[lane] = len(lane_findings)
            for finding in lane_findings:
                source_id = str(finding.get("id", "unknown"))
                finding["id"] = f"{lane}:{source_id}"
                finding["lane"] = lane
                finding["metadata"] = {
                    **dict(finding.get("metadata") or {}),
                    "audit_lane": lane,
                    "source_finding_id": source_id,
                }
            findings.extend(lane_findings)

        if handoff:
            handoff.summary = (
                f"Audit completed in {len(lane_specs)} parallel lanes with "
                f"{len(findings)} findings"
            )
        else:
            handoff = base_agent.create_handoff(
                to_agent="merge",
                summary=f"Audit completed with {len(findings)} findings",
                work_completed=["Parallel audit lanes", "Evidence candidate collection"],
            )

        return AgentResult.success_result(
            data={
                "findings": findings,
                "findings_by_lane": {
                    lane: [item for item in findings if item.get("lane") == lane]
                    for lane in lane_counts
                },
                "audit_summary": {
                    "total_candidates": sum(
                        int(child_results[lane].data.get("audit_summary", {}).get("total_candidates", 0))
                        for lane in lane_counts
                    ),
                    "reportable_findings": len(findings),
                    "confirmed_findings": sum(
                        int(child_results[lane].data.get("audit_summary", {}).get("confirmed_findings", 0))
                        for lane in lane_counts
                    ),
                    "needs_evidence_findings": sum(
                        int(child_results[lane].data.get("audit_summary", {}).get("needs_evidence_findings", 0))
                        for lane in lane_counts
                    ),
                    "rejected_candidates": sum(
                        int(child_results[lane].data.get("audit_summary", {}).get("rejected_candidates", 0))
                        for lane in lane_counts
                    ),
                    "react_reviews": sum(
                        int(child_results[lane].data.get("audit_summary", {}).get("react_reviews", 0))
                        for lane in lane_counts
                    ),
                    "react_review_stats": {
                        key: sum(
                            int(
                                child_results[lane].data.get("audit_summary", {})
                                .get("react_review_stats", {}).get(key, 0)
                            )
                            for lane in lane_counts
                        )
                        for key in (
                            "total", "completed", "degraded", "failed", "rejected", "budget_skipped",
                        )
                    },
                    "react_review_budget": (
                        shared_review_budget.to_dict() if shared_review_budget is not None else None
                    ),
                    "react_discovery": {
                        lane: deepcopy(
                            child_results[lane].data.get("audit_summary", {}).get("react_discovery", {})
                        )
                        for lane in lane_counts
                    },
                    "container_scanners": {
                        lane: deepcopy(
                            child_results[lane].data.get("audit_summary", {}).get("container_scanners", {})
                        )
                        for lane in lane_counts
                    },
                    **({
                        "dependency_scanners": {
                            lane: deepcopy(
                                child_results[lane].data.get("audit_summary", {}).get("dependency_scanner", {})
                            )
                            for lane in lane_counts
                        },
                    } if payload.get("allow_dependency_network", False) else {}),
                    "lanes": lane_counts,
                    "execution_mode": "parallel_lanes",
                    "parent_task_id": parent_task_id,
                    "task_ids": list(graph_result.tasks),
                },
                "audit_task_ids": list(graph_result.tasks),
            },
            handoff=handoff,
        )

    async def _run_agent_task(
        self,
        *,
        phase: OrchestrationPhase,
        agent_type: AgentType,
        agent: BaseAgent,
        payload: dict[str, Any],
    ) -> AgentResult:
        """Run one phase agent through the bounded task runtime."""
        if not self.orch_config.enable_agent_runtime:
            return await asyncio.wait_for(
                agent.run(payload),
                timeout=self.orch_config.phase_timeout_seconds,
            )

        task = AgentTask(
            agent_name=agent.config.name,
            phase=phase.value,
            input_payload=dict(payload),
            max_attempts=self.orch_config.agent_max_attempts,
            completion_contract={},
            metadata={"agent_type": agent_type.value},
        )
        last_result: AgentResult | None = None

        async def handler(current_task: AgentTask, context: dict[str, Any]) -> AgentResult:
            nonlocal last_result
            del current_task, context
            last_result = await agent.run(payload)
            return last_result

        def checkpoint_sink(current_task: AgentTask, checkpoint: dict[str, Any]) -> None:
            if self.state.session:
                self.state.session.checkpoint(f"agent_task:{phase.value}", checkpoint)
                if self.session_store:
                    self.session_store.save(self.state.session)

        def transition_sink(transition) -> None:
            self._record_event(
                "agent_state_transition",
                phase,
                transition.reason,
                transition.to_dict(),
            )

        loop = AgentTaskLoop(
            max_turns=self.orch_config.agent_max_turns,
            timeout_seconds=self.orch_config.phase_timeout_seconds,
            loop_repeat_limit=self.orch_config.agent_loop_repeat_limit,
            guard=AgentGuard(ReasoningGuard()),
            checkpoint_sink=checkpoint_sink,
            transition_sink=transition_sink,
        )
        runtime_result = await asyncio.wait_for(
            loop.run(
                task,
                handler,
                context={
                    "phase": phase.value,
                    "project_path": payload.get("project_path", ""),
                },
            ),
            timeout=self.orch_config.phase_timeout_seconds,
        )
        if runtime_result.status != "completed" or last_result is None or not last_result.success:
            raise ValueError(
                f"Agent task {agent_type.value} ended with {runtime_result.status}: "
                f"{runtime_result.error or task.last_error or 'completion contract rejected'}"
            )
        return last_result

    async def _run_verification_fanout(
        self,
        *,
        agent_type: AgentType,
        agent: BaseAgent,
        payload: dict[str, Any],
    ) -> AgentResult:
        """Verify findings as independently resumable child tasks."""
        findings = list(payload.get("findings_to_verify", []))
        parent_task_id = f"verification-{self.state.session.session_id if self.state.session else 'run'}"
        child_results: dict[str, AgentResult] = {}

        def checkpoint_sink(current_task: AgentTask, checkpoint: dict[str, Any]) -> None:
            if self.state.session:
                self.state.session.checkpoint("agent_task:verification", checkpoint)
                if self.session_store:
                    self.session_store.save(self.state.session)

        def transition_sink(transition) -> None:
            self._record_event(
                "agent_state_transition",
                OrchestrationPhase.VERIFICATION,
                transition.reason,
                transition.to_dict(),
            )

        def loop_factory() -> AgentTaskLoop:
            return AgentTaskLoop(
                max_turns=self.orch_config.agent_max_turns,
                timeout_seconds=self.orch_config.phase_timeout_seconds,
                loop_repeat_limit=self.orch_config.agent_loop_repeat_limit,
                guard=AgentGuard(ReasoningGuard()),
                checkpoint_sink=checkpoint_sink,
                transition_sink=transition_sink,
            )

        graph = TaskGraphController(
            max_concurrency=self.orch_config.verification_concurrency,
            loop_factory=loop_factory,
        )
        for finding in findings:
            finding_id = str(finding.get("id", "unknown"))
            task = AgentTask(
                agent_name=agent.config.name,
                parent_task_id=parent_task_id,
                phase=OrchestrationPhase.VERIFICATION.value,
                input_payload={"finding_id": finding_id},
                max_attempts=self.orch_config.agent_max_attempts,
                metadata={"agent_type": agent_type.value, "finding_id": finding_id},
            )
            child_payload = {**payload, "findings_to_verify": [deepcopy(finding)]}

            async def handler(current_task, context, *, child_payload=child_payload, finding_id=finding_id):
                del current_task, context
                result = await agent.run(child_payload)
                child_results[finding_id] = result
                return result

            graph.add_task(task, handler)

        graph_result = await asyncio.wait_for(
            graph.run(context={"phase": "verification", "project_path": payload.get("project_path", "")}),
            timeout=self.orch_config.phase_timeout_seconds,
        )
        if graph_result.status != "completed":
            failed = ", ".join(f"{key}: {value}" for key, value in graph_result.errors.items())
            raise ValueError(f"Verification child tasks failed: {failed}")

        verified_findings = []
        rejected_findings = []
        needs_evidence_findings = []
        handoff = None
        for finding_id in [str(item.get("id", "unknown")) for item in findings]:
            result = child_results[finding_id]
            verified_findings.extend(result.data.get("verified_findings", []))
            rejected_findings.extend(result.data.get("rejected_findings", []))
            needs_evidence_findings.extend(result.data.get("needs_evidence_findings", []))
            handoff = handoff or result.handoff

        if handoff:
            handoff.summary = (
                f"Verification completed for {len(findings)} findings: "
                f"{len(verified_findings)} verified, {len(rejected_findings)} rejected, "
                f"{len(needs_evidence_findings)} needs evidence"
            )
        return AgentResult.success_result(
            data={
                "verified_findings": verified_findings,
                "rejected_findings": rejected_findings,
                "needs_evidence_findings": needs_evidence_findings,
                "verification_summary": {
                    "total": len(findings),
                    "verified": len(verified_findings),
                    "rejected": len(rejected_findings),
                    "needs_evidence": len(needs_evidence_findings),
                    "execution_mode": "parallel_child_tasks",
                },
                "verification_task_ids": [
                    task_id for task_id in graph_result.tasks
                ],
            },
            handoff=handoff,
        )

    async def _run_merge_phase(self) -> None:
        """
        合并审计阶段的结果

        不运行任何 Agent，只是合并之前的审计结果。
        """
        logger.info("Running merge phase")

        self.state.current_phase = OrchestrationPhase.MERGE
        self._record_event("phase_started", OrchestrationPhase.MERGE, "Merging audit lanes")

        # 收集所有审计阶段的 findings
        all_findings = self._collect_audit_findings()

        # Retain normalized lane output and derive a conservative review queue.
        # The cluster carries source finding ids and task ids, so no evidence is
        # silently hidden when repeated scanners report the same code location.
        self.state.raw_findings = [
            normalize_finding(finding, index=index)
            for index, finding in enumerate(all_findings, 1)
        ]
        unique_findings = cluster_findings(self.state.raw_findings)

        # 保存到状态
        surface_result = self.state.phase_results.get(OrchestrationPhase.SURFACE)
        surface_object = surface_result.data.get("runtime_surface_object") if surface_result else None
        if surface_object:
            try:
                from ..surface.risk_chain import RiskChainBuilder

                chains = RiskChainBuilder(surface_object).build_risk_chains(unique_findings)
                chains_by_id = {chain.finding_id: chain.to_dict() for chain in chains}
                for finding in unique_findings:
                    finding["risk_chain"] = chains_by_id.get(finding["id"])
            except Exception as exc:
                logger.warning("Risk-chain attachment failed: %s", exc)

        graph_nodes = self.state.runtime_surface_graph.get("nodes", [])
        for finding in unique_findings:
            file_path = finding.get("file_path", "").replace("\\", "/")
            line = int(finding.get("line_start", 0) or 0)
            matched_node_ids = [
                node.get("id")
                for node in graph_nodes
                if str(node.get("attributes", {}).get("file_path", "")).replace("\\", "/") == file_path
                and int(node.get("attributes", {}).get("line_start", 0) or 0) <= line <= int(
                    node.get("attributes", {}).get("line_end", line) or line
                )
            ][:5]
            finding["surface_node_ids"] = matched_node_ids
            if not matched_node_ids:
                finding["surface_attachment_reason"] = "No runtime-surface node matched the source file and line"

        project_path_for_suppression = (
            self.state.session.project_path if self.state.session else ""
        )
        merged_findings, self._suppressed_findings = apply_suppressions(
            unique_findings, project_path_for_suppression
        )
        self.state.merged_findings = merged_findings
        self.state.lane_findings = group_findings_by_lane(self.state.merged_findings)
        if self.state.session:
            self.state.session.phases_completed.append(OrchestrationPhase.MERGE.value)
            self.state.session.checkpoint(
                OrchestrationPhase.MERGE.value,
                {
                    "raw_finding_count": len(self.state.raw_findings),
                    "finding_count": len(unique_findings),
                    "lanes": {k: len(v) for k, v in self.state.lane_findings.items()},
                },
            )
            self._record_event("phase_completed", OrchestrationPhase.MERGE, "Audit lanes merged")

        logger.info(
            "Built %s review clusters from %s raw audit findings",
            len(unique_findings), len(self.state.raw_findings),
        )

    def _phase_to_agent_type(self, phase: OrchestrationPhase) -> AgentType:
        """将阶段映射到 Agent 类型"""
        mapping = {
            OrchestrationPhase.RECON: AgentType.RECON,
            OrchestrationPhase.SURFACE: AgentType.SURFACE,
            OrchestrationPhase.AUDIT: AgentType.AUDIT,
            OrchestrationPhase.MERGE: AgentType.AUDIT,  # Merge 也由 AuditAgent 处理
            OrchestrationPhase.VERIFICATION: AgentType.VERIFICATION,
            OrchestrationPhase.REMEDIATION: AgentType.REMEDIATION,
            OrchestrationPhase.REGRESSION: AgentType.REGRESSION,
        }
        return mapping.get(phase)

    # Maximum number of characters injected per handoff section.  Each section
    # is truncated independently so one verbose handoff cannot crowd out others.
    _HANDOFF_SECTION_CHAR_LIMIT = 1500
    # Hard ceiling on the total prior_handoffs string injected into payload.
    _HANDOFF_TOTAL_CHAR_LIMIT = 6000

    @staticmethod
    def _truncate_handoff(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[:limit] + f"\n… [truncated {len(text) - limit} chars]"

    def _build_phase_payload(
        self,
        phase: OrchestrationPhase,
        original_payload: dict[str, Any],
    ) -> dict[str, Any]:
        """
        构建阶段特定的输入数据

        将前序阶段的 handoff 信息注入到 payload 中。
        每个 handoff section 独立截断至 _HANDOFF_SECTION_CHAR_LIMIT 字符，
        整体 prior_handoffs 字符串不超过 _HANDOFF_TOTAL_CHAR_LIMIT，
        防止随流程推进上下文无界增长。
        """
        payload = {**original_payload}

        # 注入前序阶段的 handoff 上下文（只注入与当前阶段相关的前驱）
        _relevant_phases = {
            OrchestrationPhase.SURFACE: [OrchestrationPhase.RECON],
            OrchestrationPhase.AUDIT: [OrchestrationPhase.RECON, OrchestrationPhase.SURFACE],
            OrchestrationPhase.VERIFICATION: [OrchestrationPhase.SURFACE, OrchestrationPhase.AUDIT],
            OrchestrationPhase.REMEDIATION: [OrchestrationPhase.AUDIT, OrchestrationPhase.VERIFICATION],
            OrchestrationPhase.REGRESSION: [OrchestrationPhase.VERIFICATION, OrchestrationPhase.REMEDIATION],
        }
        phases_to_include = _relevant_phases.get(phase, list(self.state.phase_handoffs.keys()))
        handoff_context_parts = []
        for prev_phase in phases_to_include:
            if prev_phase in self.state.phase_handoffs:
                raw_text = self.state.phase_handoffs[prev_phase].to_prompt_context()
                handoff_context_parts.append(
                    self._truncate_handoff(raw_text, self._HANDOFF_SECTION_CHAR_LIMIT)
                )

        if handoff_context_parts:
            combined = "\n\n".join(handoff_context_parts)
            payload["prior_handoffs"] = self._truncate_handoff(combined, self._HANDOFF_TOTAL_CHAR_LIMIT)

        # 阶段特定的数据
        if phase == OrchestrationPhase.VERIFICATION:
            # 验证阶段需要合并后的 findings
            payload["findings_to_verify"] = self._filter_findings_for_verification()
            payload["runtime_surface_graph"] = self.state.runtime_surface_graph
            payload["threat_model"] = self.state.runtime_threat_model
            payload["project_profile"] = self.state.project_profile
            provider = str(getattr(self.llm_service, "provider", "custom")).lower()
            payload["enable_react_verification"] = bool(
                payload.get("use_llm", False)
                and self.orch_config.enable_react_verification
                and provider != "mock"
            )

        elif phase == OrchestrationPhase.AUDIT:
            payload["runtime_surface_graph"] = self.state.runtime_surface_graph
            payload["threat_model"] = self.state.runtime_threat_model
            provider = str(getattr(self.llm_service, "provider", "custom")).lower()
            payload["enable_react_review"] = bool(
                payload.get("use_llm", False)
                and self.orch_config.enable_react_audit
                and provider != "mock"
            )
            payload["enable_react_discovery"] = bool(
                payload.get("enable_react_discovery", payload["enable_react_review"])
                and payload["enable_react_review"]
            )
            payload["llm_deep_analysis_limit"] = max(
                1, min(5, int(payload.get("llm_deep_analysis_limit", 2) or 2))
            )

        elif phase == OrchestrationPhase.REMEDIATION:
            # 整改阶段需要验证后的 findings
            payload["verified_findings"] = [
                *self.state.verified_findings,
                *self.state.needs_evidence_findings,
            ]
            self._attach_runtime_context(payload["verified_findings"])
            payload["runtime_surface_graph"] = self.state.runtime_surface_graph
            payload["threat_model"] = self.state.runtime_threat_model
            payload["session_id"] = self.state.session.session_id if self.state.session else ""

        elif phase == OrchestrationPhase.REGRESSION:
            # 回归测试阶段需要已完成的整改包
            payload["completed_packages"] = self.state.remediation_bundles

        return payload

    def _collect_audit_findings(self) -> list[dict[str, Any]]:
        """收集所有审计阶段的 findings"""
        findings = []

        if OrchestrationPhase.AUDIT in self.state.phase_results:
            audit_result = self.state.phase_results[OrchestrationPhase.AUDIT]
            findings.extend(audit_result.data.get("findings", []))

        return findings

    def _filter_findings_for_verification(self) -> list[dict[str, Any]]:
        """筛选需要验证的 findings"""
        all_findings = self.state.merged_findings

        # 按置信度筛选
        filtered = [
            f for f in all_findings
            if f.get("confidence", 0) >= self.orch_config.verification_threshold
        ]

        # 按严重性排序（优先验证高危）
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        filtered.sort(key=lambda f: severity_order.get(f.get("severity", "low"), 4))

        base_budget = max(0, int(self.orch_config.max_verification_count))
        fraction = min(max(float(self.orch_config.verification_fraction), 0.0), 1.0)
        adaptive_budget = max(base_budget, int(math.ceil(len(filtered) * fraction)))
        selected = self._select_verification_candidates(
            filtered,
            min(len(filtered), adaptive_budget),
        )
        selected_ids = {str(item.get("id", "")) for item in selected}
        self.state.not_reviewed_findings = []
        for finding in all_findings:
            if str(finding.get("id", "")) in selected_ids:
                continue
            deferred = dict(finding)
            deferred["verification_status"] = "not_reviewed"
            deferred["verification_reason"] = (
                "below_verification_threshold"
                if float(finding.get("confidence", 0) or 0) < self.orch_config.verification_threshold
                else "verification_budget_exceeded"
            )
            self.state.not_reviewed_findings.append(deferred)
        return selected

    def _select_verification_candidates(
        self,
        findings: list[dict[str, Any]],
        budget: int,
    ) -> list[dict[str, Any]]:
        """Return a severity-prioritized batch with bounded per-type coverage."""
        if budget <= 0:
            return []
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ordered = sorted(
            findings,
            key=lambda item: (
                severity_order.get(str(item.get("severity", "low")).lower(), 4),
                -float(item.get("confidence", 0) or 0),
            ),
        )
        selected: list[dict[str, Any]] = []
        selected_ids: set[str] = set()
        quota_by_type: dict[str, int] = {}
        per_type_quota = max(0, int(self.orch_config.verification_sample_per_type))

        if per_type_quota:
            for finding in ordered:
                vuln_type = str(finding.get("vulnerability_type", "unknown")).lower()
                if quota_by_type.get(vuln_type, 0) >= per_type_quota:
                    continue
                selected.append(finding)
                selected_ids.add(str(finding.get("id", "")))
                quota_by_type[vuln_type] = quota_by_type.get(vuln_type, 0) + 1
                if len(selected) >= budget:
                    return selected

        for finding in ordered:
            finding_id = str(finding.get("id", ""))
            if finding_id in selected_ids:
                continue
            selected.append(finding)
            selected_ids.add(finding_id)
            if len(selected) >= budget:
                break
        return selected

    def _run_return_phase(self) -> None:
        """Build the stable payload sent back to the coding context."""
        self.state.current_phase = OrchestrationPhase.RETURN
        self.state.returned_packages = build_return_packages(
            [*self.state.verified_findings, *self.state.needs_evidence_findings],
            self.state.remediation_bundles,
        )
        if self.state.session:
            self.state.session.phases_completed.append(OrchestrationPhase.RETURN.value)
            self.state.session.checkpoint(
                OrchestrationPhase.RETURN.value,
                {"package_count": len(self.state.returned_packages)},
            )
            self._record_event("phase_completed", OrchestrationPhase.RETURN, "Remediation packages prepared")

    def _attach_runtime_context(self, findings: list[dict[str, Any]]) -> None:
        """Bind remediation work to the evidence-backed VRTM path, not just a file line."""
        observations_by_finding: dict[str, list[dict[str, Any]]] = {}
        for observation in self.state.runtime_graph_observations:
            finding_id = str((observation.get("facts") or {}).get("finding_id", ""))
            if finding_id:
                observations_by_finding.setdefault(finding_id, []).append(observation)
        hypotheses = {
            str(item.get("id")): item
            for item in self.state.runtime_threat_model.get("hypotheses", [])
            if item.get("id")
        }
        for finding in findings:
            observation_records = observations_by_finding.get(str(finding.get("id", "")), [])
            node_ids = sorted({str(item.get("target_id")) for item in observation_records if item.get("target_id")})
            hypothesis_ids = sorted({
                str(hypothesis_id)
                for item in observation_records
                for hypothesis_id in item.get("hypothesis_ids", []) or []
                if hypothesis_id in hypotheses
            })
            linked_hypotheses = [hypotheses[item] for item in hypothesis_ids]
            if node_ids:
                finding["surface_node_ids"] = node_ids
            if hypothesis_ids:
                finding["risk_hypothesis_ids"] = hypothesis_ids
            if not finding.get("risk_chain") and linked_hypotheses:
                hypothesis = linked_hypotheses[0]
                finding["risk_chain"] = {
                    "source_signal": hypothesis.get("source_signal", "runtime surface signal"),
                    "boundary_path": list(hypothesis.get("attack_path", []) or []),
                    "impact_hypothesis": hypothesis.get("impact", "Security impact requires verification"),
                    "hypothesis_id": hypothesis.get("id"),
                }
            finding["runtime_risk_context"] = {
                "surface_node_ids": node_ids,
                "risk_hypothesis_ids": hypothesis_ids,
                "control_gaps": sorted({
                    str(gap)
                    for hypothesis in linked_hypotheses
                    for gap in hypothesis.get("control_gaps", []) or []
                }),
                "evidence_predicates": [
                    predicate
                    for hypothesis in linked_hypotheses
                    for predicate in hypothesis.get("evidence_predicates", []) or []
                ],
            }

    def _attach_regression_status(self) -> None:
        reports = {report.get("package_id"): report for report in self.state.regression_reports}
        bundles = {bundle.get("finding_id"): bundle for bundle in self.state.remediation_bundles}
        for finding in [*self.state.verified_findings, *self.state.needs_evidence_findings]:
            bundle = bundles.get(finding.get("id"), {})
            report = reports.get(bundle.get("package_id"))
            if report:
                finding["regression_status"] = report.get("overall_status", "unknown")

    def _build_final_result(self) -> AgentResult:
        """构建最终结果"""
        closure_policy = ClosurePolicy()
        for finding in self.state.verified_findings:
            finding["closure"] = closure_policy.evaluate(finding)
        returned_by_finding = {
            package.get("finding", {}).get("id"): package
            for package in self.state.returned_packages
        }
        for finding in self.state.verified_findings:
            package = returned_by_finding.get(finding.get("id"))
            if package:
                package["closure"] = finding.get("closure")

        terminal_findings = [
            *self.state.verified_findings,
            *self.state.rejected_findings,
            *self.state.needs_evidence_findings,
            *self.state.not_reviewed_findings,
        ]
        terminal_ids = [str(item.get("id", "")) for item in terminal_findings]
        candidate_ids = [str(item.get("id", "")) for item in self.state.merged_findings]
        if len(terminal_ids) != len(set(terminal_ids)) or set(terminal_ids) != set(candidate_ids):
            raise ValueError("Final finding dispositions do not conserve the merged candidate set")
        verification_summary = {
            "total_candidates": len(candidate_ids),
            "verified": len(self.state.verified_findings),
            "rejected": len(self.state.rejected_findings),
            "needs_evidence": len(self.state.needs_evidence_findings),
            "not_reviewed": len(self.state.not_reviewed_findings),
            "deferred_by_reason": {
                reason: sum(
                    item.get("verification_reason") == reason
                    for item in self.state.not_reviewed_findings
                )
                for reason in {item.get("verification_reason", "unknown") for item in self.state.not_reviewed_findings}
            },
            "conserved": True,
        }

        return AgentResult.success_result(
            data={
                "orchestration_completed": True,
                "phases_completed": self.state.session.phases_completed if self.state.session else [],
                "merged_findings": self.state.merged_findings,
                "suppressed_findings": getattr(self, "_suppressed_findings", []),
                "raw_findings": self.state.raw_findings,
                "verified_findings": self.state.verified_findings,
                "rejected_findings": self.state.rejected_findings,
                "needs_evidence_findings": self.state.needs_evidence_findings,
                "not_reviewed_findings": self.state.not_reviewed_findings,
                "verification_summary": verification_summary,
                "remediation_bundles": self.state.remediation_bundles,
                "regression_reports": self.state.regression_reports,
                "project_profile": self.state.project_profile,
                "runtime_surface_graph": self.state.runtime_surface_graph,
                "threat_model": self.state.runtime_threat_model,
                "runtime_graph_observations": self.state.runtime_graph_observations,
                "vrtm_evolution": self.state.vrtm_evolution,
                "llm_runtime": {
                    "provider": str(getattr(self.llm_service, "provider", "unknown")),
                    "model": str(getattr(self.llm_service, "model", "unknown")),
                    "real_provider": str(getattr(self.llm_service, "provider", "mock")).lower() != "mock",
                    "react_audit_enabled": bool(self.orch_config.enable_react_audit),
                    "react_verification_enabled": bool(
                        self.orch_config.enable_react_verification
                        and str(getattr(self.llm_service, "provider", "mock")).lower() != "mock"
                    ),
                },
                "audit_lanes": {lane: len(items) for lane, items in self.state.lane_findings.items()},
                "audit_summary": (
                    self.state.phase_results.get(OrchestrationPhase.AUDIT).data.get("audit_summary", {})
                    if self.state.phase_results.get(OrchestrationPhase.AUDIT)
                    else {}
                ),
                "audit_task_ids": (
                    self.state.phase_results.get(OrchestrationPhase.AUDIT).data.get("audit_task_ids", [])
                    if self.state.phase_results.get(OrchestrationPhase.AUDIT)
                    else []
                ),
                "returned_packages": self.state.returned_packages,
                "audit_request": dict(self.state.audit_request),
                "session": self.state.session.to_dict() if self.state.session else None,
                "summary": self._generate_summary(),
                "findings": terminal_findings,
            },
            metadata={
                "total_phases": len(self.state.phase_results),
                "total_findings": len(self.state.merged_findings),
                "verified_findings_count": len(self.state.verified_findings),
                "remediation_bundles_count": len(self.state.remediation_bundles),
                "regression_reports_count": len(self.state.regression_reports),
            },
        )

    def _collect_partial_results(self) -> dict[str, Any]:
        """收集部分结果（用于失败情况）"""
        return {
            "phases_completed": [
                phase.value
                for phase, result in self.state.phase_results.items()
                if result.success
            ],
            "merged_findings": self.state.merged_findings,
            "error_phase": self.state.current_phase.value,
            "error": self.state.error,
            "session": self.state.session.to_dict() if self.state.session else None,
        }

    def _generate_summary(self) -> str:
        """生成审查摘要"""
        total_findings = len(self.state.merged_findings)
        verified_findings = len(self.state.verified_findings)

        severity_counts = {}
        for finding in self.state.verified_findings:
            severity = finding.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        summary_parts = [
            "Security audit completed.",
            f"Total findings: {total_findings}",
            f"Verified findings: {verified_findings}",
        ]

        if severity_counts:
            summary_parts.append("Severity breakdown:")
            for severity, count in sorted(severity_counts.items()):
                summary_parts.append(f"  - {severity}: {count}")

        return " ".join(summary_parts)
