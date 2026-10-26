"""
Vibe Sec Platform — 入口脚本

提供 CLI 接口和快速启动功能。
"""

import asyncio
import json
import logging
import os
import sys
import uuid
from pathlib import Path
from typing import Any

from core.agents.base import AgentConfig, AgentType
from core.agents.registry import AgentRegistry
from core.llm_service import MockLLMService
from core.orchestrator.orchestrator import OrchestrationConfig, OrchestratorAgent
from core.policy.trigger_policy import TriggerPolicy
from core.session.models import RunSession
from core.session.store import SessionStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)


def _default_skill_session_dir() -> str:
    """Keep Skill sessions durable without requiring every host to supply a path."""
    state_root = Path(os.getenv("VIBE_SEC_STATE_HOME", str(Path.home() / ".vibe-sec"))).resolve()
    return str(state_root / "sessions")


def setup_agent_registry(llm_service=None, event_emitter=None) -> AgentRegistry:
    """
    设置 Agent 注册表

    Args:
        llm_service: LLM 服务
        event_emitter: 事件发射器

    Returns:
        注册了所有 Agent 的注册表
    """
    from agents.audit_agent import AuditAgent
    from agents.recon_agent import ReconAgent
    from agents.regression_agent import RegressionAgent
    from agents.remediation_agent import RemediationAgent
    from agents.surface_agent import SurfaceAgent
    from agents.verification_agent import VerificationAgent

    registry = AgentRegistry()

    # 注册 ReconAgent
    registry.register(
        agent_type=AgentType.RECON,
        agent_class=ReconAgent,
        enabled=True,
        priority=10,
    )

    # 注册 SurfaceAgent
    registry.register(
        agent_type=AgentType.SURFACE,
        agent_class=SurfaceAgent,
        dependencies=[AgentType.RECON],
        enabled=True,
        priority=9,
    )

    # 注册 AuditAgent
    registry.register(
        agent_type=AgentType.AUDIT,
        agent_class=AuditAgent,
        dependencies=[AgentType.SURFACE],
        enabled=True,
        priority=5,
    )

    # 注册 VerificationAgent
    registry.register(
        agent_type=AgentType.VERIFICATION,
        agent_class=VerificationAgent,
        dependencies=[AgentType.AUDIT],
        enabled=True,
        priority=4,
    )

    # 注册 RemediationAgent
    registry.register(
        agent_type=AgentType.REMEDIATION,
        agent_class=RemediationAgent,
        dependencies=[AgentType.VERIFICATION],
        enabled=True,
        priority=3,
    )

    # 注册 RegressionAgent
    registry.register(
        agent_type=AgentType.REGRESSION,
        agent_class=RegressionAgent,
        dependencies=[AgentType.REMEDIATION],
        enabled=True,
        priority=2,
    )

    # 创建 Agent 实例
    for agent_type in registry.list_agents():
        registration = registry.get_registration(agent_type)
        if registration:
            agent = registration.agent_class(
                config=AgentConfig(
                    name=f"{agent_type.value}_agent",
                    agent_type=agent_type,
                ),
                llm_service=llm_service,
                event_emitter=event_emitter,
            )
            registry.set_instance(agent_type, agent)

    return registry


async def run_audit(
    project_path: str,
    *,
    audit_scope: dict[str, bool] | None = None,
    output_format: str = "markdown",
    use_llm: bool = False,
    api_key: str | None = None,
    llm_config: dict[str, Any] | None = None,
    llm_deep_analysis_limit: int = 2,
    react_review_limit: int | None = None,
    discovery_target_limit: int | None = None,
    react_max_turns: int | None = None,
    max_verification_count: int | None = None,
    verification_fraction: float | None = None,
    enable_react_discovery: bool | None = None,
    verbose: bool = False,
    session_dir: str | None = None,
    enable_container_tools: bool = False,
    allow_dependency_network: bool = False,
    changed_files: list[str] | None = None,
    trigger: str = "explicit",
    persist_vrtm: bool = False,
    verification_authorization: dict[str, Any] | None = None,
    enable_react_audit: bool = False,
    enable_react_verification: bool = False,
    session_metadata: dict[str, Any] | None = None,
    exclude_patterns: list[str] | None = None,
) -> dict[str, Any]:
    """
    执行安全审查

    Args:
        project_path: 项目路径
        audit_scope: 审计范围配置
        output_format: 输出格式
        use_llm: 是否使用 LLM
        api_key: Legacy DeepSeek API key for CLI usage
        llm_config: API-local model configuration selected by the UI
        verbose: 是否输出详细信息

    Returns:
        审查结果
    """
    resolved_project = os.path.abspath(project_path)
    if not os.path.isdir(resolved_project):
        raise ValueError(f"project_path must be an existing directory: {project_path}")
    project_path = resolved_project

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # 设置 LLM 服务
    llm_service = None
    if use_llm:
        if llm_config:
            from core.llm_service import create_configured_llm_service

            llm_service = create_configured_llm_service(**llm_config)
        else:
            configured_api_key = (
                api_key
                or os.getenv("VIBE_SEC_DEEPSEEK_API_KEY")
                or os.getenv("DEEPSEEK_API_KEY")
            )
            if configured_api_key:
                from core.llm_service import DeepSeekService
                llm_service = DeepSeekService(api_key=configured_api_key)
                if getattr(llm_service, "client", None) is None:
                    raise RuntimeError("DeepSeek LLM support requires the 'openai' package")
            else:
                raise ValueError(
                    "--use-llm requires an active local Chat model configuration, "
                    "--api-key, VIBE_SEC_DEEPSEEK_API_KEY, or DEEPSEEK_API_KEY"
                )

    # 设置 Agent 注册表
    registry = setup_agent_registry(llm_service=llm_service)

    session_store = SessionStore(session_dir) if session_dir else None

    # 创建编排器
    orchestrator = OrchestratorAgent(
        llm_service=llm_service or MockLLMService(),
        agent_registry=registry,
        config=OrchestrationConfig(
            enable_recon=True,
            enable_surface=True,
            enable_audit=True,
            enable_verification=True,
            enable_remediation=True,
            # Regression is a post-fix operation invoked through `retest`.
            enable_regression=False,
            parallel_audit=True,
            verification_threshold=0.5,
            max_verification_count=(
                max(0, int(max_verification_count))
                if max_verification_count is not None else 20
            ),
            verification_fraction=(
                min(1.0, max(0.0, float(verification_fraction)))
                if verification_fraction is not None else 0.30
            ),
            # The interactive Skill enables bounded evidence sessions explicitly.
            # The management UI stays on its bounded fast path unless it opts in.
            enable_react_audit=bool(enable_react_audit),
            enable_react_verification=bool(enable_react_verification),
        ),
        session_store=session_store,
    )

    # 执行审计
    logger.info(f"Starting audit for project: {project_path}")
    # AST 通道首跑预检：未就绪时给出双分支指引（在线预热 / 离线降级），
    # 不阻断审计——各泳道自带正则降级路径。
    from core.languages.tree_sitter_gateway import status as _tree_sitter_status

    ts_status = _tree_sitter_status()
    if not ts_status.get("all_ready"):
        logger.info(f"AST lane not ready: {ts_status.get('hint')}")
    result = await orchestrator.run({
        "project_path": project_path,
        "audit_scope": audit_scope or {
            "web_vulns": True,
            "agent_vulns": True,
            "mcp_vulns": True,
            "secret_leaks": True,
            "workflow_vulns": True,
        },
        "output_format": output_format,
        "use_llm": use_llm,
        "llm_deep_analysis_limit": max(1, min(5, int(llm_deep_analysis_limit))),
        "react_review_limit": (
            max(0, int(react_review_limit)) if react_review_limit is not None else None
        ),
        "discovery_target_limit": (
            max(0, int(discovery_target_limit)) if discovery_target_limit is not None else None
        ),
        "react_max_turns": (
            max(2, min(15, int(react_max_turns))) if react_max_turns is not None else None
        ),
        "react_verification_max_turns": (
            max(2, min(12, int(react_max_turns))) if react_max_turns is not None else None
        ),
        "enable_react_discovery": (
            bool(enable_react_discovery) if enable_react_discovery is not None else bool(enable_react_audit)
        ),
        "enable_container_tools": enable_container_tools,
        "allow_dependency_network": allow_dependency_network,
        "trigger": trigger,
        "changed_files": list(changed_files or []),
        "verification_authorization": dict(verification_authorization or {}),
        "session_metadata": dict(session_metadata or {}),
        "exclude_patterns": list(exclude_patterns or []),
    })

    if not result.success:
        raise RuntimeError(
            str(result.metadata.get("error") or result.data.get("error") or "Audit orchestration failed")
        )

    # 排除可见性回显：.vibe-secignore 来自被审计项目，恶意仓库可携带全排除
    # 文件静默压制检出——生效模式与来源必须随结果对使用者可见（对抗边界）。
    from core.audit.path_exclusion import load_ignore_file, resolve_excludes

    ignore_file_present = bool(load_ignore_file(project_path))
    effective_patterns = resolve_excludes(project_path, exclude_patterns)
    result.data["exclusion"] = {
        "patterns": effective_patterns,
        "pattern_count": len(effective_patterns),
        "ignore_file_present": ignore_file_present,
        "warning": (
            ".vibe-secignore 来自被审计项目，可能压制检出——请人工核认其内容"
            if ignore_file_present else ""
        ),
    }

    # AST 泳道降级显式化：解析器获取失败的语言回填结果契约，避免消费者
    # 误以为跑的是全精度 AST 分析（实际已降级为正则通道）。
    from core.languages.tree_sitter_gateway import degraded_languages as _ast_degraded_languages

    ast_degraded = _ast_degraded_languages()
    if ast_degraded:
        degradation = {
            "languages": ast_degraded,
            "impact": "AST 泳道已降级为正则分析，该语言协议分析精度可能下降",
            "hint": (
                "受限网络可设置 VIBE_SEC_TREE_SITTER_CACHE 指向预置解析器缓存目录，"
                "或设置 VIBE_SEC_DISABLE_TREE_SITTER=1 显式跳过 AST 通道"
            ),
        }
        result.data["ast_degradation"] = degradation
        logger.warning(f"AST lane degraded for languages: {', '.join(ast_degraded)}")

    if persist_vrtm:
        from core.vrtm import VRTMService

        vrtm_model = await VRTMService(project_path).build(
            trusted_observations=result.data.get("runtime_graph_observations", []),
            persist=True,
        )
        result.data["vrtm_model"] = vrtm_model
        result.data["vrtm_snapshot"] = vrtm_model.get("snapshot")
        result.data["runtime_surface_graph"] = vrtm_model["graph"]
        result.data["threat_model"] = vrtm_model["threat_model"]

    if orchestrator.state.session:
        session = orchestrator.state.session
        snapshot = dict(result.data.get("vrtm_snapshot") or {})
        package_summaries = []
        for bundle in result.data.get("remediation_bundles", []) or []:
            metadata = dict(bundle.get("metadata") or {})
            metadata["session_id"] = session.session_id
            if snapshot:
                metadata["vrtm_baseline_snapshot"] = snapshot
            bundle["metadata"] = metadata
            bundle["session_id"] = session.session_id
            if snapshot:
                bundle["vrtm_baseline_snapshot"] = snapshot
            package_summaries.append({
                "package_id": bundle.get("package_id"),
                "finding_id": bundle.get("finding_id"),
                "state": bundle.get("state", "draft"),
                "approval_required": bool(dict(bundle.get("approval_gate") or {}).get("required", False)),
            })
        session.update_metadata(
            audit_request=dict(result.data.get("audit_request") or {}),
            verification_summary=dict(result.data.get("verification_summary") or {}),
            llm_runtime=dict(result.data.get("llm_runtime") or {}),
            remediation_packages=package_summaries,
            vrtm={
                "snapshot": snapshot,
                "previous_snapshot": result.data.get("vrtm_model", {}).get("previous_snapshot"),
                "model_id": result.data.get("vrtm_model", {}).get("model_id"),
                "quality_status": result.data.get("vrtm_model", {}).get("status"),
                "security_change_analysis": result.data.get("vrtm_model", {}).get("security_change_analysis", {}),
            } if result.data.get("vrtm_model") else {},
        )
        session.emit(
            "audit_completed", "completed", "Audit, VRTM, and remediation state are ready for the Skill host",
            {"returned_package_count": len(result.data.get("returned_packages", []) or []), "vrtm_snapshot": snapshot.get("id")},
        )
        session.checkpoint(
            "completed",
            {
                "verification_summary": result.data.get("verification_summary", {}),
                "remediation_package_ids": [item.get("package_id") for item in package_summaries],
                "vrtm_snapshot": snapshot,
            },
        )
        result.data["session"] = session.to_dict()
        if session_store:
            session_store.save(session)

    return result.data


def _normalize_changed_files(project_path: str, changed_files: list[str] | None) -> list[str]:
    root = Path(project_path).resolve()
    normalized = []
    for value in changed_files or []:
        raw = Path(str(value))
        target = raw.resolve() if raw.is_absolute() else (root / raw).resolve()
        try:
            relative = target.relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError(f"changed file escapes project root: {value}") from exc
        if relative not in normalized:
            normalized.append(relative)
    return normalized


async def run_skill_audit(
    project_path: str,
    *,
    changed_files: list[str] | None = None,
    suggest_only: bool = False,
    use_llm: bool = False,
    session_dir: str | None = None,
    enable_container_tools: bool = False,
    allow_dependency_network: bool = False,
    verification_authorization: dict[str, Any] | None = None,
    llm_review_candidate_limit: int = 2,
    llm_verification_limit: int = 2,
    llm_max_turns: int = 4,
    llm_discovery_target_limit: int = 0,
    full_result: bool = False,
) -> dict[str, Any]:
    """Stable Skill-host contract for trigger decisions and remediation return."""
    normalized = _normalize_changed_files(project_path, changed_files)
    decision = TriggerPolicy(project_path).evaluate(normalized, explicit=not suggest_only)
    envelope: dict[str, Any] = {
        "contract_version": "vibe-sec.skill-result.v2",
        "project_path": str(Path(project_path).resolve()),
        "trigger_decision": decision.to_dict(),
        "scope": {
            "mode": "changed_files_with_transitive_security_context" if normalized else "project",
            "changed_files": normalized,
        },
        "audit_executed": False,
    }
    if suggest_only:
        return envelope
    effective_session_dir = session_dir or _default_skill_session_dir()
    result = await run_audit(
        project_path,
        output_format="json",
        use_llm=use_llm,
        react_review_limit=llm_review_candidate_limit if use_llm else None,
        discovery_target_limit=llm_discovery_target_limit if use_llm else None,
        react_max_turns=llm_max_turns if use_llm else None,
        max_verification_count=llm_verification_limit if use_llm else None,
        verification_fraction=0.0 if use_llm else None,
        enable_react_discovery=bool(use_llm and llm_discovery_target_limit > 0),
        session_dir=effective_session_dir,
        enable_container_tools=enable_container_tools,
        allow_dependency_network=allow_dependency_network,
        changed_files=normalized,
        trigger="skill_explicit",
        persist_vrtm=True,
        verification_authorization=verification_authorization,
        enable_react_audit=use_llm,
        enable_react_verification=use_llm,
        session_metadata={
            "schema": "vibe-sec.skill-session.v1",
            "entrypoint": "skill-audit",
            "changed_files": normalized,
            "scope_mode": envelope["scope"]["mode"],
            "llm_requested": bool(use_llm),
        },
    )
    _mark_skill_packages_dispatched(result)
    compact = _compact_skill_result(result)
    session_ref = _record_skill_return_session(result, compact, effective_session_dir)
    envelope.update({
        "audit_executed": True,
        "run_id": compact["run_id"],
        "audit_summary": compact["audit_summary"],
        "verification_summary": result.get("verification_summary", {}),
        "returned_packages": compact["returned_packages"],
        "full_result_ref": compact["full_result_ref"],
        "session": session_ref,
        "retest": {
            "required": bool(compact["returned_packages"]),
            "session_id": session_ref["session_id"],
            "session_dir": effective_session_dir,
            "vrtm_baseline_snapshot": dict(result.get("vrtm_snapshot") or {}),
        },
    })
    if full_result:
        envelope["audit_result"] = result
    return envelope


def _compact_skill_result(result: dict[str, Any]) -> dict[str, Any]:
    from core.tool_fabric import ArtifactStore

    session = dict(result.get("session") or {})
    run_id = str(session.get("session_id") or f"run-{uuid.uuid4().hex}")
    state_root = Path(os.getenv("VIBE_SEC_STATE_HOME", str(Path.home() / ".vibe-sec"))).resolve()
    store = ArtifactStore(str(state_root / "artifacts"), session_id=run_id)
    full_artifact = store.put_json(
        result,
        producer="skill-audit",
        artifact_type="full_audit_result",
        file_name="audit-result.json",
    )
    compact_packages = []
    for package in result.get("returned_packages", []) or []:
        finding = dict(package.get("finding") or {})
        remediation = dict(package.get("remediation") or {})
        evidence = dict(package.get("evidence") or {})
        detail = store.put_json(
            package,
            producer="skill-audit",
            artifact_type="finding_return_package",
            file_name=f"{finding.get('id', 'finding')}.json",
            metadata={"finding_id": finding.get("id")},
        )
        compact_packages.append({
            "finding": finding,
            "verification": {
                "status": finding.get("verification_status", "needs_evidence"),
                "predicate": remediation.get("verification_predicate", ""),
                "evidence_level": evidence.get("level", 0),
                "gaps": list(evidence.get("gaps", []) or [])[:10],
            },
            "remediation": {
                key: remediation.get(key)
                for key in (
                    "schema", "schema_version", "package_id", "finding_id", "ai_patch_prompt",
                    "change_scope", "patch_constraints", "acceptance_criteria",
                    "positive_retest_cases", "negative_retest_cases", "expected_surface_change",
                )
            },
            "return_contract": dict(package.get("return_contract") or {}),
            "delivery": {
                "state": remediation.get("state", "dispatched"),
                "session_id": session.get("session_id"),
                "requires_human_confirmation": bool(
                    dict(package.get("return_contract") or {}).get("requires_human_confirmation", False)
                ),
            },
            "detail_ref": {
                "artifact_id": detail.artifact_id,
                "path": detail.path,
                "sha256": detail.sha256,
                "size_bytes": detail.size_bytes,
            },
        })
    return {
        "run_id": run_id,
        "audit_summary": {
            "candidate_count": len(result.get("merged_findings", []) or []),
            **dict(result.get("verification_summary") or {}),
            "returned_package_count": len(compact_packages),
            "quality": "degraded" if result.get("needs_evidence_findings") else "complete",
        },
        "returned_packages": compact_packages,
        "full_result_ref": {
            "artifact_id": full_artifact.artifact_id,
            "path": full_artifact.path,
            "sha256": full_artifact.sha256,
            "size_bytes": full_artifact.size_bytes,
        },
    }


def _mark_skill_packages_dispatched(result: dict[str, Any]) -> None:
    """Record that packages have entered the coding context; no fix is implied."""
    session_id = str(dict(result.get("session") or {}).get("session_id") or "")
    for bundle in result.get("remediation_bundles", []) or []:
        bundle["state"] = "dispatched"
        metadata = dict(bundle.get("metadata") or {})
        metadata["session_id"] = session_id
        metadata["delivery_state"] = "dispatched"
        bundle["metadata"] = metadata
    for package in result.get("returned_packages", []) or []:
        remediation = dict(package.get("remediation") or {})
        remediation["state"] = "dispatched"
        package["remediation"] = remediation


def _record_skill_return_session(
    result: dict[str, Any], compact: dict[str, Any], session_dir: str,
) -> dict[str, Any]:
    """Append the Skill return boundary after artifacts and dispatch state exist."""
    session_data = dict(result.get("session") or {})
    if not session_data:
        raise RuntimeError("Skill audit completed without a RunSession")
    session = RunSession.from_dict(session_data)
    store = SessionStore(session_dir)
    packages = [
        {
            "package_id": item.get("remediation", {}).get("package_id"),
            "finding_id": item.get("finding", {}).get("id"),
            "state": item.get("delivery", {}).get("state", "dispatched"),
            "requires_human_confirmation": item.get("delivery", {}).get("requires_human_confirmation", False),
        }
        for item in compact.get("returned_packages", [])
    ]
    session.update_metadata(
        skill_return={
            "contract_version": "vibe-sec.skill-result.v2",
            "full_result_ref": compact.get("full_result_ref"),
            "packages": packages,
        }
    )
    session.emit(
        "remediation_dispatched", "return", "Evidence-bound remediation packages returned to the coding context",
        {"package_count": len(packages), "full_result_artifact": compact.get("full_result_ref", {}).get("artifact_id")},
    )
    session.checkpoint(
        "return",
        {"package_count": len(packages), "package_ids": [item.get("package_id") for item in packages]},
    )
    store.save(session)
    result["session"] = session.to_dict()
    return store.reference(session)


async def run_retest(
    project_path: str,
    remediation_packages: list[dict[str, Any]],
    *,
    run_project_tests: bool = True,
    test_command: list[str] | None = None,
    baseline_ref: str | None = None,
    update_vrtm: bool = True,
    session_dir: str | None = None,
    session_id: str | None = None,
    approval_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Run Harness-controlled post-fix checks and persist the closure decision."""
    resolved_project = os.path.abspath(project_path)
    if not os.path.isdir(resolved_project):
        raise ValueError(f"project_path must be an existing directory: {project_path}")
    from agents.regression_agent import RegressionAgent

    packages = [dict(item) for item in remediation_packages or [] if isinstance(item, dict)]
    session_store, session = _load_retest_session(
        resolved_project, session_id=session_id, session_dir=session_dir,
    )
    if session:
        _validate_retest_packages_for_session(packages, session)
        session.start()
        session.emit(
            "retest_started", "retest", "Harness started post-fix regression and VRTM closure checks",
            {"package_count": len(packages)},
        )
        session.checkpoint(
            "retest_started",
            {"package_ids": [item.get("package_id") for item in packages]},
        )
        session_store.save(session)

    approvals = _load_retest_approvals(
        approval_paths or [], resolved_project, session_id=session.session_id if session else "",
        package_ids=[str(item.get("package_id", "")) for item in packages],
    ) if session else {}

    result = await RegressionAgent().run({
        "project_path": resolved_project,
        "completed_packages": packages,
        "run_project_tests": run_project_tests,
        "test_command": test_command,
        "baseline_ref": baseline_ref,
    })
    if not result.success:
        raise RuntimeError(result.error or "Regression Agent failed")

    reports = list(result.data.get("regression_reports", []) or [])
    closure_records = _evaluate_retest_closure(
        packages, reports, session_id=session.session_id if session else None, approvals=approvals,
    )
    eligible_findings = [
        _trusted_mitigation_finding(item["package"])
        for item in closure_records
        if item["pre_vrtm_eligible"]
    ]

    vrtm_model = None
    if update_vrtm:
        from core.vrtm import VRTMService

        service = VRTMService(resolved_project)
        baseline = _load_retest_vrtm_baseline(service, session, packages)
        # Check the post-fix graph before admitting any mitigation claim. An
        # authority/control regression keeps every package open for review.
        preflight = await service.build(previous_result=baseline, persist=False)
        surface_requires_review = bool(
            preflight.get("security_change_analysis", {}).get("requires_security_review", False)
        )
        vrtm_model = await service.build(
            previous_result=baseline,
            trusted_findings=[] if surface_requires_review else eligible_findings,
            persist=True,
        )
        _finalize_vrtm_closure(
            closure_records,
            accepted_finding_ids=_accepted_retest_finding_ids(vrtm_model),
            surface_requires_review=surface_requires_review,
        )
        result.data["vrtm_preflight"] = preflight
        result.data["vrtm_model"] = vrtm_model
    else:
        _finalize_vrtm_closure(
            closure_records,
            accepted_finding_ids=set(),
            surface_requires_review=False,
            vrtm_disabled=True,
        )

    closure = _closure_summary(closure_records)
    result.data["closure"] = closure
    result.data["updated_remediation_packages"] = packages
    if session:
        _record_retest_session(
            session,
            reports=reports,
            closure=closure,
            vrtm_model=vrtm_model,
            packages=packages,
        )
        session.complete()
        session_store.save(session)
        result.data["session"] = session_store.reference(session)
    return result.data


def _load_retest_session(
    project_path: str, *, session_id: str | None, session_dir: str | None,
) -> tuple[SessionStore | None, RunSession | None]:
    if not session_id:
        return None, None
    store = SessionStore(session_dir or _default_skill_session_dir())
    session = store.load(session_id)
    if Path(session.project_path).resolve() != Path(project_path).resolve():
        raise ValueError("RunSession is bound to a different project")
    return store, session


def _validate_retest_packages_for_session(
    packages: list[dict[str, Any]], session: RunSession,
) -> None:
    known_ids = {
        str(item.get("package_id", ""))
        for item in session.metadata.get("remediation_packages", []) or []
        if isinstance(item, dict) and item.get("package_id")
    }
    skill_return = dict(session.metadata.get("skill_return") or {})
    known_ids.update(
        str(item.get("package_id", ""))
        for item in skill_return.get("packages", []) or []
        if isinstance(item, dict) and item.get("package_id")
    )
    for package in packages:
        package_id = str(package.get("package_id", ""))
        if not package_id:
            raise ValueError("Each remediation package requires package_id for a RunSession retest")
        package_session = str(dict(package.get("metadata") or {}).get("session_id") or "")
        if package_session and package_session != session.session_id:
            raise ValueError(f"Remediation package {package_id} is bound to a different RunSession")
        if known_ids and package_id not in known_ids:
            raise ValueError(f"Remediation package {package_id} was not issued by this RunSession")


def _load_retest_approvals(
    approval_paths: list[str], project_path: str, *, session_id: str, package_ids: list[str],
) -> dict[str, dict[str, Any]]:
    from core.remediation import load_remediation_approval

    approvals: dict[str, dict[str, Any]] = {}
    expected_ids = {item for item in package_ids if item}
    for path in approval_paths:
        # The raw JSON is used only to select the package. The signed loader
        # verifies the project, session, package, expiry, and local signature.
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid remediation approval: {exc}") from exc
        package_id = str(raw.get("package_id", "")) if isinstance(raw, dict) else ""
        if package_id not in expected_ids:
            raise ValueError("Remediation approval does not match a submitted package")
        approvals[package_id] = load_remediation_approval(
            path, project_path, session_id=session_id, package_id=package_id,
        )
    return approvals


def _evaluate_retest_closure(
    packages: list[dict[str, Any]], reports: list[dict[str, Any]], *,
    session_id: str | None, approvals: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    reports_by_id = {str(item.get("package_id", "")): item for item in reports}
    records = []
    for package in packages:
        package_id = str(package.get("package_id", ""))
        report = reports_by_id.get(package_id, {})
        approval_gate = dict(package.get("approval_gate") or {})
        if not approval_gate:
            approval_gate = dict(dict(package.get("metadata") or {}).get("approval_gate") or {})
        blockers = []
        if not session_id:
            blockers.append("RunSession is required before a remediation can be closed")
        if str(package.get("state", "draft")) not in {"completed", "returned"}:
            blockers.append("Coding agent has not returned a completed remediation state")
        if dict(package.get("fix_result") or {}).get("status") != "fixed":
            blockers.append("No fix_result.status=fixed was returned by the coding agent")
        blockers.extend(_retest_evidence_binding_blockers(package))
        if report.get("overall_status") != "success":
            blockers.append("Regression did not pass every configured control and project test")
        if approval_gate.get("required") and package_id not in approvals:
            blockers.append("A signed local operator confirmation is required for this high-impact change")
        records.append({
            "package": package,
            "package_id": package_id,
            "finding_id": str(package.get("finding_id", "")),
            "regression_report": report,
            "approval": approvals.get(package_id),
            "blockers": blockers,
            "pre_vrtm_eligible": not blockers,
            "status": "pending_vrtm" if not blockers else "open",
        })
    return records


def _retest_evidence_binding_blockers(package: dict[str, Any]) -> list[str]:
    """Require post-fix controls to identify the package predicate they satisfy."""
    fix_result = dict(package.get("fix_result") or {})
    evidence = list(fix_result.get("retest_evidence") or [])
    required_steps = [
        item for item in package.get("retest_plan", []) or []
        if isinstance(item, dict)
        and item.get("control_id") in {"negative-exploit", "positive-behavior"}
    ]
    if not required_steps:
        return ["Remediation package has no bound positive and negative post-fix control plan"]
    blockers = []
    for step in required_steps:
        control_id = str(step.get("control_id"))
        matches = [
            item for item in evidence
            if isinstance(item, dict) and str(item.get("control_id", "")) == control_id
        ]
        if not matches:
            blockers.append(f"Missing retest evidence bound to control_id={control_id}")
            continue
        expected_predicate = str(step.get("predicate") or step.get("expected_result") or "")
        if not any(
            item.get("status") == "passed"
            and str(item.get("predicate", "")) == expected_predicate
            and _has_retest_evidence_provenance(item)
            for item in matches
        ):
            blockers.append(f"Retest evidence for control_id={control_id} does not satisfy the planned predicate")
    return blockers


def _has_retest_evidence_provenance(record: dict[str, Any]) -> bool:
    return bool(str(record.get("predicate", "")).strip()) and any(
        record.get(key)
        for key in (
            "artifact_ref", "artifact_refs", "tool_execution_id", "execution_id",
            "trace_ref", "screenshot_ref",
        )
    )


def _trusted_mitigation_finding(package: dict[str, Any]) -> dict[str, Any]:
    metadata = dict(package.get("metadata") or {})
    scope = dict(package.get("change_scope") or metadata.get("change_scope") or {})
    evidence = list(dict(package.get("fix_result") or {}).get("retest_evidence") or [])
    return {
        "id": str(package.get("finding_id", "")),
        "file_path": package.get("file_path") or metadata.get("affected_file"),
        "line_start": package.get("line_start", 0),
        "vulnerability_type": package.get("vulnerability_type") or metadata.get("vulnerability_type"),
        "severity": package.get("severity", metadata.get("severity", "medium")),
        "verification_status": "verified",
        "verdict": "confirmed",
        "remediation_status": "mitigated",
        "verification_predicate": "Harness passed negative exploit, positive behavior, scope, and project-test closure gates.",
        "confidence": 0.98,
        "surface_node_ids": list(package.get("surface_node_ids", []) or metadata.get("surface_node_ids", []) or []),
        "risk_hypothesis_ids": list(
            package.get("risk_hypothesis_ids", []) or scope.get("risk_hypothesis_ids", []) or []
        ),
        "evidence_bundle": {"items": evidence, "gaps": []},
    }


def _load_retest_vrtm_baseline(
    service: Any, session: RunSession | None, packages: list[dict[str, Any]],
) -> dict[str, Any] | None:
    snapshot: dict[str, Any] = {}
    if session:
        snapshot = dict(dict(session.metadata.get("vrtm") or {}).get("snapshot") or {})
    if not snapshot:
        for package in packages:
            snapshot = dict(package.get("vrtm_baseline_snapshot") or {})
            if snapshot:
                break
    snapshot_id = str(snapshot.get("id", ""))
    if not snapshot_id:
        return None
    try:
        return service.store.load(snapshot_id)
    except (OSError, ValueError) as exc:
        raise ValueError(f"VRTM baseline snapshot is unavailable for retest: {exc}") from exc


def _accepted_retest_finding_ids(vrtm_model: dict[str, Any]) -> set[str]:
    application = dict(vrtm_model.get("retest_observation_application") or {})
    accepted = set(application.get("accepted_observation_ids", []) or [])
    if not accepted:
        return set()
    values = []
    for node in vrtm_model.get("graph", {}).get("nodes", []) or []:
        values.extend(dict(node.get("attributes") or {}).get("observations", []) or [])
    return {
        str(dict(item.get("facts") or {}).get("finding_id", ""))
        for item in values
        if isinstance(item, dict) and item.get("id") in accepted
    }


def _finalize_vrtm_closure(
    records: list[dict[str, Any]], *, accepted_finding_ids: set[str],
    surface_requires_review: bool, vrtm_disabled: bool = False,
) -> None:
    for record in records:
        package = record["package"]
        if not record["pre_vrtm_eligible"]:
            package["closure"] = {"status": "open", "blockers": record["blockers"]}
            continue
        if vrtm_disabled:
            record["blockers"].append("Post-fix VRTM validation was disabled")
        elif surface_requires_review:
            record["blockers"].append("Post-fix VRTM detected a security-significant surface change requiring review")
        elif record["finding_id"] not in accepted_finding_ids:
            record["blockers"].append("Post-fix VRTM could not bind mitigation evidence to the current runtime surface")
        if record["blockers"]:
            record["status"] = "open"
            package["closure"] = {"status": "open", "blockers": record["blockers"]}
            continue
        record["status"] = "closed"
        package["state"] = "returned"
        package["closure"] = {
            "status": "closed",
            "session_id": package.get("session_id") or dict(package.get("metadata") or {}).get("session_id"),
            "approval": record["approval"],
            "regression_status": record["regression_report"].get("overall_status"),
            "vrtm_mitigation_bound": True,
        }


def _closure_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    packages = [
        {
            "package_id": item["package_id"],
            "finding_id": item["finding_id"],
            "status": item["status"],
            "blockers": list(item["blockers"]),
            "regression_status": item["regression_report"].get("overall_status"),
            "approval": item["approval"],
        }
        for item in records
    ]
    return {
        "schema": "vibe-sec.remediation-closure.v1",
        "closed_count": sum(item["status"] == "closed" for item in packages),
        "open_count": sum(item["status"] != "closed" for item in packages),
        "packages": packages,
    }


def _record_retest_session(
    session: RunSession, *, reports: list[dict[str, Any]], closure: dict[str, Any],
    vrtm_model: dict[str, Any] | None, packages: list[dict[str, Any]],
) -> None:
    status_by_id = {item["package_id"]: item for item in closure.get("packages", []) or []}
    package_states = []
    for package in packages:
        package_id = str(package.get("package_id", ""))
        state = status_by_id.get(package_id, {})
        package_states.append({
            "package_id": package_id,
            "finding_id": package.get("finding_id"),
            "delivery_state": package.get("state", "draft"),
            "closure_status": state.get("status", "open"),
            "blockers": state.get("blockers", []),
        })
    session.update_metadata(
        retest={
            "regression_reports": reports,
            "closure": closure,
            "packages": package_states,
            "vrtm": {
                "snapshot": dict(vrtm_model.get("snapshot") or {}) if vrtm_model else {},
                "model_id": vrtm_model.get("model_id") if vrtm_model else None,
                "security_change_analysis": vrtm_model.get("security_change_analysis", {}) if vrtm_model else {},
            },
        }
    )
    session.emit(
        "retest_completed", "retest", "Harness recorded regression, VRTM, and closure outcomes",
        {"closed_count": closure.get("closed_count", 0), "open_count": closure.get("open_count", 0)},
    )
    session.checkpoint(
        "retest_completed",
        {"closure": closure, "vrtm_snapshot": dict(vrtm_model.get("snapshot") or {}) if vrtm_model else {}},
    )


async def run_vrtm_model(
    project_path: str,
    *,
    declaration_path: str | None = None,
    observations: list[dict[str, Any]] | None = None,
    baseline: str | None = None,
    store_dir: str | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Build a standalone, versioned VRTM model without running the audit pipeline."""
    from core.vrtm import VRTMModelStore, VRTMService

    service = VRTMService(project_path, store_root=store_dir)
    previous = None
    if baseline:
        baseline_path = Path(baseline)
        if baseline_path.is_file():
            value = json.loads(baseline_path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("VRTM baseline file must contain an object")
            previous = value
        else:
            previous = VRTMModelStore(project_path, root=store_dir).load(baseline)
    return await service.build(
        declaration_path=declaration_path,
        observations=observations,
        previous_result=previous,
        persist=persist,
    )


def initialize_vrtm_declaration(project_path: str, *, force: bool = False) -> str:
    """Create the minimal project-owned declaration used to fill runtime unknowns."""
    root = Path(project_path).resolve()
    if not root.is_dir():
        raise ValueError(f"project_path must be an existing directory: {project_path}")
    target = root / ".vibe-sec" / "vrtm.yaml"
    if target.exists() and not force:
        raise FileExistsError(f"VRTM declaration already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "schema: vibe-sec.vrtm.declaration.v1\n"
        "scope:\n"
        "  environment: development\n"
        "nodes: []\n"
        "edges: []\n"
        "assumptions: []\n"
        "exclusions: []\n",
        encoding="utf-8",
    )
    return str(target)


def _load_vrtm_observations(paths: list[str]) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for path in paths:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        items = payload if isinstance(payload, list) else payload.get("observations", []) if isinstance(payload, dict) else None
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise ValueError(f"observation file must contain a list or observations list: {path}")
        values.extend(dict(item) for item in items)
    return values


def format_result(result: dict[str, Any], format_type: str = "markdown") -> str:
    """生成格式化的报告"""
    from core.reporting.output_formatter import OutputFormatter

    formatter = OutputFormatter()
    return formatter.format(result, format_type)


def _persist_full_audit_result(result: dict[str, Any]):
    """把完整审计结果归档到本地 ArtifactStore，供瘦身报告回读。"""
    from core.tool_fabric import ArtifactStore

    state_root = Path(os.getenv("VIBE_SEC_STATE_HOME", str(Path.home() / ".vibe-sec"))).resolve()
    run_id = str(dict(result.get("session") or {}).get("session_id") or f"run-{uuid.uuid4().hex}")
    store = ArtifactStore(str(state_root / "artifacts"), session_id=run_id)
    return store.put_json(
        result,
        producer="cli-audit",
        artifact_type="full_audit_result",
        file_name="audit-result.json",
    )


def _slim_audit_payload(result: dict[str, Any], full_artifact: Any) -> dict[str, Any]:
    """紧凑版 JSON 报告：只保留摘要与 finding 概要，完整结果经 ref 引用。

    真实仓库的全量 JSON 可达数百 MB（bundle/VRTM 全部内联），默认报告文件
    只保留可读摘要；retest 输入会经 full_result_ref 自动回读完整整改包。
    """
    findings = result.get("merged_findings", []) or []
    finding_fields = (
        "id", "vulnerability_type", "severity", "file_path", "line_start", "line_end",
        "description", "verification_status", "confidence", "cwe_id", "risk_hypothesis_ids",
    )
    return {
        "contract_version": "vibe-sec.audit-report.v1",
        "summary": result.get("summary"),
        "audit_summary": result.get("audit_summary"),
        "verification_summary": result.get("verification_summary"),
        "audit_lanes": result.get("audit_lanes"),
        "finding_count": len(findings),
        "findings": [
            {key: finding.get(key) for key in finding_fields if key in finding}
            for finding in findings
        ],
        "remediation_package_ids": [
            bundle.get("package_id") for bundle in result.get("remediation_bundles", []) or []
        ],
        "needs_evidence_finding_count": len(result.get("needs_evidence_findings", []) or []),
        # 可见性/可审计性贯穿瘦身形态：排除回显（对抗边界：ignore 文件来自
        # 被审计项目）与抑制条目概要不得因瘦身而丢失。
        "exclusion": result.get("exclusion"),
        "suppressed_finding_count": len(result.get("suppressed_findings", []) or []),
        "suppressed_findings": [
            {
                "vulnerability_type": (item.get("finding") or {}).get("vulnerability_type"),
                "file_path": (item.get("finding") or {}).get("file_path"),
                "line_start": (item.get("finding") or {}).get("line_start"),
                "suppression_reason": (item.get("suppression") or {}).get("reason"),
            }
            for item in result.get("suppressed_findings", []) or []
        ],
        "full_result_ref": {
            "artifact_id": full_artifact.artifact_id,
            "path": full_artifact.path,
            "sha256": full_artifact.sha256,
            "size_bytes": full_artifact.size_bytes,
        },
        "retest_usage": "vibe-sec retest <project> --input <本文件> 会经 full_result_ref 自动回读完整整改包",
    }


def _extract_retest_packages(payload: Any) -> list:
    """兼容三种 retest 输入：完整审计结果、瘦身报告（含 full_result_ref）、裸包列表。"""
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    packages = payload.get("remediation_bundles")
    if isinstance(packages, list) and packages:
        return packages
    ref = dict(payload.get("full_result_ref") or {})
    ref_path = Path(str(ref.get("path") or ""))
    if ref_path.is_file():
        hydrated = json.loads(ref_path.read_text(encoding="utf-8-sig"))
        packages = hydrated.get("remediation_bundles", []) if isinstance(hydrated, dict) else []
        if isinstance(packages, list) and packages:
            return packages
    return []


def _print_deployment_report(report: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
        return
    print(f"Vibe Sec {report.get('contract_version', 'deployment')} - {report.get('status', 'unknown')}")
    if report.get("reason"):
        print(f"Reason: {report['reason']}")
    for action in report.get("actions", []):
        suffix = f": {action.get('reason')}" if action.get("reason") else ""
        print(f"[{str(action.get('status', 'unknown')).upper()}] {action.get('id')}{suffix}")
    doctor = report.get("doctor", report)
    docker = doctor.get("docker", {})
    docker_text = f"ready ({docker.get('server_version')})" if docker.get("daemon_available") else "unavailable"
    print(f"Docker: {docker_text}")
    for image in doctor.get("images", []):
        state = "READY" if image.get("available") else "OPTIONAL" if not image.get("default_install") else "BLOCKED"
        print(f"[{state}] {image.get('id')} -> {image.get('image')} ({image.get('reason')})")
    llm = doctor.get("llm", {})
    print(f"LLM credentials: {'configured' if llm.get('configured') else 'not configured'}")
    capabilities = doctor.get("capabilities")
    if capabilities:
        print("Capabilities:")
        for name, info in capabilities.items():
            state = "READY" if info.get("available") else ("OPTIONAL" if info.get("optional") else "DEGRADED")
            suffix = ""
            if not info.get("available"):
                parts = list(info.get("blocking") or [])
                if info.get("fallback"):
                    parts.append(f"fallback: {info['fallback']}")
                if info.get("next_step"):
                    parts.append(f"next: {info['next_step']}")
                suffix = f" ({'; '.join(parts)})" if parts else ""
            print(f"  [{state}] {name}{suffix}")


def main():
    """CLI 入口"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Vibe Sec Platform - 安全审查验证平台",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 审查项目
  python -m main audit /path/to/project

  # 审查项目并输出 Markdown 报告
  python -m main audit /path/to/project --format markdown --output report.md

  # 使用 LLM 增强分析
  python -m main audit /path/to/project --use-llm
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="命令")

    setup_parser = subparsers.add_parser("setup", help="Prepare and verify the local Vibe Sec runtime")
    setup_parser.add_argument("--tool", action="append", default=[], help="Install one image id; repeat as needed")
    setup_parser.add_argument("--include-codeql", action="store_true", help="Also install the optional CodeQL image")
    setup_parser.add_argument("--force", action="store_true", help="Rebuild selected images even when accepted")
    setup_parser.add_argument("--dry-run", action="store_true", help="Print the deterministic install plan only")
    setup_parser.add_argument("--json", action="store_true", help="Emit the machine-readable setup contract")

    doctor_parser = subparsers.add_parser("doctor", help="Check runtime, image, and credential readiness")
    doctor_parser.add_argument("--json", action="store_true", help="Emit the machine-readable doctor contract")

    update_parser = subparsers.add_parser("update-tools", help="Refresh and verify managed tool images")
    update_parser.add_argument("--tool", action="append", default=[], help="Update one image id; repeat as needed")
    update_parser.add_argument("--include-codeql", action="store_true", help="Also update the optional CodeQL image")
    update_parser.add_argument("--dry-run", action="store_true", help="Print the deterministic update plan only")
    update_parser.add_argument("--json", action="store_true", help="Emit the machine-readable setup contract")

    # audit 命令
    audit_parser = subparsers.add_parser("audit", help="执行安全审查")
    audit_parser.add_argument("project_path", help="项目路径")
    audit_parser.add_argument("--format", default="markdown", choices=["markdown", "json", "claude_code", "html", "sarif"], help="输出格式")
    audit_parser.add_argument("--output", "-o", help="输出文件路径")
    audit_parser.add_argument("--use-llm", action="store_true", help="使用 LLM 增强分析")
    audit_parser.add_argument("--api-key", help="LLM API Key")
    audit_parser.add_argument("--session-dir", help="保存 JSONL 会话快照的目录")
    audit_parser.add_argument(
        "--container-tools",
        action="store_true",
        help="Enable the focused container scanner tool profile",
    )
    audit_parser.add_argument(
        "--osv",
        action="store_true",
        help="Authorize fixed-endpoint dependency vulnerability queries to api.osv.dev",
    )
    audit_parser.add_argument(
        "--no-model-store", action="store_true",
        help="Do not persist the evidence-enriched VRTM model after audit",
    )
    audit_parser.add_argument(
        "--full-result", action="store_true",
        help="Write the full JSON result inline (default: compact report with a full_result_ref)",
    )
    audit_parser.add_argument(
        "--exclude", action="append", default=[],
        help="Project-relative exclude pattern (gitignore-like, repeatable); "
        "combined with .vibe-secignore and built-in defaults (*.min.js, *.map, dist/)",
    )
    audit_parser.add_argument("--verbose", "-v", action="store_true", help="输出详细信息")
    audit_parser.add_argument("--authorization", help="Trusted verification authorization envelope")

    retest_parser = subparsers.add_parser("retest", help="Run post-fix remediation regression checks")
    retest_parser.add_argument("project_path", help="Project directory after applying fixes")
    retest_parser.add_argument("--input", "-i", required=True, help="JSON audit result or remediation package list")
    retest_parser.add_argument("--output", "-o", help="Write the JSON regression report to this path")
    retest_parser.add_argument("--baseline-ref", help="Git baseline used to collect the changed tree")
    retest_parser.add_argument(
        "--test-command",
        nargs=argparse.REMAINDER,
        help="Approved argument-vector project test command; place this option last",
    )
    retest_parser.add_argument("--skip-project-tests", action="store_true", help="Skip project test execution")
    retest_parser.add_argument("--skip-vrtm", action="store_true", help="Skip post-fix VRTM rebuild and diff")
    retest_parser.add_argument("--session-id", help="RunSession that issued the remediation packages")
    retest_parser.add_argument("--session-dir", help="Directory containing the RunSession JSONL snapshots")
    retest_parser.add_argument(
        "--approval", action="append", default=[],
        help="Signed local remediation approval; repeat for each high-impact package",
    )

    suppress_parser = subparsers.add_parser(
        "suppress", help="Record a local finding suppression for one project",
    )
    suppress_parser.add_argument("project_path", help="Audited project directory")
    suppress_parser.add_argument("--type", required=True, dest="vulnerability_type")
    suppress_parser.add_argument("--file", required=True)
    suppress_parser.add_argument("--line", type=int, default=None)
    suppress_parser.add_argument("--reason", required=True)
    suppress_parser.add_argument(
        "--list", action="store_true", dest="list_entries", help="List suppressions for the project",
    )

    approval_parser = subparsers.add_parser(
        "approve-remediation", help="Issue a signed local confirmation for one high-impact remediation package",
    )
    approval_parser.add_argument("project_path", help="Audited project directory")
    approval_parser.add_argument("--session-id", required=True, help="RunSession that issued the package")
    approval_parser.add_argument("--session-dir", help="Directory containing the RunSession JSONL snapshots")
    approval_parser.add_argument("--package-id", required=True, help="Remediation package to approve")
    approval_parser.add_argument("--reason", required=True, help="Operator confirmation reason")
    approval_parser.add_argument("--approved-by", default="local_operator", help="Local operator identity label")
    approval_parser.add_argument("--ttl-minutes", type=int, default=480)
    approval_parser.add_argument("--output", help="Approval file path outside the audited project")

    skill_parser = subparsers.add_parser(
        "skill-audit", help="Run the stable Skill trigger/audit/remediation return contract",
    )
    skill_parser.add_argument("project_path", help="Project directory")
    skill_parser.add_argument(
        "--changed-file", action="append", default=[],
        help="Project-relative changed file; repeat for multiple files",
    )
    skill_parser.add_argument("--authorization", help="Trusted verification authorization envelope")
    skill_parser.add_argument("--full-result", action="store_true", help="Include the full audit object in stdout")

    authorize_parser = subparsers.add_parser(
        "authorize-verification", help="Issue a short-lived local verification authorization",
    )
    authorize_parser.add_argument("project_path", help="Project directory")
    authorize_parser.add_argument("--output", help="Authorization output path outside the project")
    authorize_parser.add_argument("--ttl-minutes", type=int, default=15)
    authorize_parser.add_argument("--allow-service-start", action="store_true")
    authorize_parser.add_argument("--allow-network", action="store_true")
    authorize_parser.add_argument("--target-scope", action="append", default=[])
    skill_parser.add_argument(
        "--suggest-only", action="store_true",
        help="Return a conservative trigger suggestion without starting an audit",
    )
    skill_parser.add_argument("--use-llm", action="store_true", help="Use the configured LLM provider")
    skill_parser.add_argument("--session-dir", help="Save JSONL session snapshots")
    skill_parser.add_argument(
        "--container-tools", action="store_true", help="Enable focused container scanners",
    )
    skill_parser.add_argument(
        "--osv", action="store_true",
        help="Authorize fixed-endpoint dependency vulnerability queries to api.osv.dev",
    )

    model_parser = subparsers.add_parser(
        "model", help="Build and version a VRTM runtime threat model",
    )
    model_parser.add_argument("project_path", help="Project directory")
    model_parser.add_argument("--declaration", help="Explicit VRTM project declaration YAML")
    model_parser.add_argument(
        "--observation", action="append", default=[],
        help="JSON observation file; repeat to merge evidence sources",
    )
    model_parser.add_argument(
        "--baseline", help="Snapshot id or VRTM result JSON used for change analysis",
    )
    model_parser.add_argument("--store-dir", help="Override the local VRTM snapshot directory")
    model_parser.add_argument("--no-store", action="store_true", help="Do not persist this model")
    model_parser.add_argument("--list-snapshots", action="store_true", help="List stored model versions")
    model_parser.add_argument("--format", choices=["json", "markdown", "dot", "mermaid"], default="json")
    model_parser.add_argument("--output", "-o", help="Write the model export to this path")
    model_parser.add_argument(
        "--fail-on-review", action="store_true",
        help="Exit with status 2 when authority expansion or control regression requires review",
    )

    model_init_parser = subparsers.add_parser(
        "model-init", help="Create a project-owned VRTM declaration template",
    )
    model_init_parser.add_argument("project_path", help="Project directory")
    model_init_parser.add_argument("--force", action="store_true", help="Replace an existing template")

    # 版本命令
    subparsers.add_parser("version", help="显示版本信息")

    args = parser.parse_args()

    if args.command in {"setup", "update-tools", "doctor"}:
        from core.deployment import DeploymentManager

        try:
            manager = DeploymentManager()
            if args.command == "doctor":
                result = manager.doctor()
            else:
                result = manager.setup(
                    include=args.tool,
                    include_codeql=args.include_codeql,
                    force=args.command == "update-tools" or args.force,
                    dry_run=args.dry_run,
                )
        except (OSError, RuntimeError, ValueError) as exc:
            result = {
                "contract_version": "vibe-sec.deployment-error.v1",
                "status": "failed",
                "reason": str(exc),
            }
        _print_deployment_report(result, as_json=args.json)
        if result.get("status") in {"failed", "blocked", "partial", "not_ready"}:
            sys.exit(1)

    elif args.command == "model-init":
        try:
            target = initialize_vrtm_declaration(args.project_path, force=args.force)
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}")
            sys.exit(1)
        print(target)

    elif args.command == "model":
        from core.vrtm import VRTMModelStore, export_vrtm

        try:
            if args.list_snapshots:
                snapshots = VRTMModelStore(args.project_path, root=args.store_dir).list_snapshots()
                output = json.dumps({"snapshots": snapshots}, ensure_ascii=False, indent=2)
                result = None
            else:
                observations = _load_vrtm_observations(args.observation)
                result = asyncio.run(run_vrtm_model(
                    args.project_path,
                    declaration_path=args.declaration,
                    observations=observations,
                    baseline=args.baseline,
                    store_dir=args.store_dir,
                    persist=not args.no_store,
                ))
                output = export_vrtm(result, args.format)
        except (FileNotFoundError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}")
            sys.exit(1)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"VRTM model saved to: {Path(args.output).resolve()}")
        else:
            print(output)
        if result and result.get("status") == "invalid":
            sys.exit(1)
        if result and args.fail_on_review and result.get("security_change_analysis", {}).get("requires_security_review"):
            sys.exit(2)

    elif args.command == "audit":
        if not os.path.exists(args.project_path):
            print(f"Error: 项目路径不存在: {args.project_path}")
            sys.exit(1)

        try:
            verification_authorization = None
            if args.authorization:
                from core.verification import load_verification_authorization
                verification_authorization = load_verification_authorization(
                    args.authorization, args.project_path,
                )
            result = asyncio.run(
                run_audit(
                    args.project_path,
                    output_format=args.format,
                    use_llm=args.use_llm,
                    api_key=args.api_key,
                    verbose=args.verbose,
                    session_dir=args.session_dir,
                    enable_container_tools=args.container_tools,
                    allow_dependency_network=args.osv,
                    persist_vrtm=not args.no_model_store,
                    verification_authorization=verification_authorization,
                    exclude_patterns=args.exclude,
                )
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"Error: {exc}")
            sys.exit(1)

        if args.format == "markdown":
            output = format_result(result, "markdown")
        elif args.format == "json":
            if args.full_result:
                output = format_result(result, "json")
            else:
                artifact = _persist_full_audit_result(result)
                output = json.dumps(
                    _slim_audit_payload(result, artifact), ensure_ascii=False, indent=2, default=str
                )
        elif args.format == "claude_code":
            output = format_result(result, "claude_code")
        elif args.format == "html":
            output = format_result(result, "html")
        elif args.format == "sarif":
            output = format_result(result, "sarif")
        else:
            output = format_result(result, "markdown")

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"报告已保存到: {args.output}")
        else:
            print(output)

    elif args.command == "retest":
        if not os.path.isdir(args.project_path):
            print(f"Error: project directory does not exist: {args.project_path}")
            sys.exit(1)
        try:
            # PowerShell commonly writes JSON with a UTF-8 BOM. Accept it at
            # the CLI boundary while keeping the parsed payload unchanged.
            with open(args.input, encoding="utf-8-sig") as handle:
                payload = json.load(handle)
            packages = _extract_retest_packages(payload)
            if not isinstance(packages, list):
                raise ValueError("input must contain a remediation_bundles list or be a package list")
            result = asyncio.run(run_retest(
                args.project_path,
                packages,
                run_project_tests=not args.skip_project_tests,
                test_command=args.test_command,
                baseline_ref=args.baseline_ref,
                update_vrtm=not args.skip_vrtm,
                session_dir=args.session_dir,
                session_id=args.session_id,
                approval_paths=args.approval,
            ))
            output = json.dumps(result, ensure_ascii=False, indent=2)
        except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
            print(f"Error: {exc}")
            sys.exit(1)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(output)
            print(f"Regression report saved to: {args.output}")
        else:
            print(output)
        if any(
            item.get("overall_status") == "failure"
            for item in result.get("regression_reports", [])
        ):
            sys.exit(2)

    elif args.command == "suppress":
        from core.audit.suppression import add_suppression, load_suppressions

        if not os.path.isdir(args.project_path):
            print(f"Error: project directory does not exist: {args.project_path}")
            sys.exit(1)
        if args.list_entries:
            print(json.dumps(load_suppressions(args.project_path), ensure_ascii=False, indent=2))
        else:
            entry = add_suppression(
                args.project_path,
                vulnerability_type=args.vulnerability_type,
                file_path=args.file,
                line=args.line,
                reason=args.reason,
            )
            print(json.dumps({"suppressed": entry}, ensure_ascii=False, indent=2))

    elif args.command == "approve-remediation":
        from core.remediation import issue_remediation_approval
        try:
            # Confirm that the local session issued this package before signing
            # a confirmation that can later satisfy the retest closure gate.
            store = SessionStore(args.session_dir or _default_skill_session_dir())
            session = store.load(args.session_id)
            if Path(session.project_path).resolve() != Path(args.project_path).resolve():
                raise ValueError("RunSession is bound to a different project")
            known_ids = {
                str(item.get("package_id", ""))
                for item in session.metadata.get("remediation_packages", []) or []
                if isinstance(item, dict)
            }
            known_ids.update(
                str(item.get("package_id", ""))
                for item in dict(session.metadata.get("skill_return") or {}).get("packages", []) or []
                if isinstance(item, dict)
            )
            if args.package_id not in known_ids:
                raise ValueError("Remediation package was not issued by this RunSession")
            result = issue_remediation_approval(
                args.project_path,
                session_id=args.session_id,
                package_id=args.package_id,
                reason=args.reason,
                approved_by=args.approved_by,
                output_path=args.output,
                ttl_minutes=args.ttl_minutes,
            )
        except (OSError, ValueError) as exc:
            print(json.dumps({"error": str(exc)}, ensure_ascii=False))
            sys.exit(1)
        print(json.dumps(result, ensure_ascii=False, indent=2))

    elif args.command == "skill-audit":
        if not os.path.isdir(args.project_path):
            print(json.dumps({"error": f"project directory does not exist: {args.project_path}"}))
            sys.exit(1)
        try:
            verification_authorization = None
            if args.authorization:
                from core.verification import load_verification_authorization
                verification_authorization = load_verification_authorization(args.authorization, args.project_path)
            result = asyncio.run(run_skill_audit(
                args.project_path,
                changed_files=args.changed_file,
                suggest_only=args.suggest_only,
                use_llm=args.use_llm,
                session_dir=args.session_dir,
                enable_container_tools=args.container_tools,
                allow_dependency_network=args.osv,
                verification_authorization=verification_authorization,
                full_result=args.full_result,
            ))
        except (RuntimeError, ValueError) as exc:
            print(json.dumps({"error": str(exc)}, ensure_ascii=False))
            sys.exit(1)
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))

    elif args.command == "authorize-verification":
        from core.verification import issue_verification_authorization
        try:
            result = issue_verification_authorization(
                args.project_path,
                output_path=args.output,
                ttl_minutes=args.ttl_minutes,
                allow_service_start=args.allow_service_start,
                allow_network=args.allow_network,
                target_scope=args.target_scope or None,
            )
        except (OSError, ValueError) as exc:
            print(json.dumps({"error": str(exc)}, ensure_ascii=False))
            sys.exit(1)
        print(json.dumps(result, ensure_ascii=False, indent=2))

    elif args.command == "version":
        from core import __version__
        print(f"Vibe Sec Platform version {__version__}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
