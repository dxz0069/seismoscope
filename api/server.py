"""
REST API 服务

提供 HTTP API 接口，支持：
- 项目管理
- 审计任务管理
- 结果查询
- 整改包管理
- 插件管理
"""

import asyncio
import os
import secrets
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

if __package__:
    from .state_store import ApiStateStore
else:
    from state_store import ApiStateStore

from core.audit.finding_cluster import cluster_findings
from core.llm_service import (
    LLMMessage,
    create_configured_llm_service,
    normalize_llm_api_key,
)

app = FastAPI(
    title="Vibe Sec Platform API",
    description="面向 Vibe Coding 范式的安全审查验证平台",
    version="0.5.0",
)

# CORS 配置
_cors_origins = [
    item.strip() for item in os.getenv(
        "VIBE_SEC_CORS_ORIGINS",
        "http://127.0.0.1:3000,http://localhost:3000,http://127.0.0.1:5173,http://localhost:5173",
    ).split(",") if item.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ========== 数据模型 ==========

class AuditScope(BaseModel):
    """审计范围"""
    web_vulns: bool = True
    agent_vulns: bool = True
    secret_leaks: bool = True


class ProjectCreate(BaseModel):
    """创建项目请求"""
    name: str
    path: str
    description: str | None = None
    audit_scope: AuditScope = AuditScope()


class Project(BaseModel):
    """项目"""
    id: str
    name: str
    path: str
    description: str | None = None
    audit_scope: AuditScope
    created_at: datetime
    updated_at: datetime


class ModelConfigCreate(BaseModel):
    """A local provider configuration submitted from the settings UI."""

    model_type: Literal["chat", "embedding"] = "chat"
    provider: Literal["openai", "openai_compatible", "anthropic", "auto"]
    api_base: str | None = Field(default=None, max_length=500)
    api_key: str = Field(min_length=1, max_length=10000, repr=False)
    model_name: str = Field(min_length=1, max_length=200)
    temperature: float = Field(default=0.2, ge=0, le=2)
    max_tokens: int = Field(default=4096, ge=1, le=32768)
    top_p: float = Field(default=0.9, ge=0, le=1)
    frequency_penalty: float = Field(default=0, ge=-2, le=2)
    presence_penalty: float = Field(default=0, ge=-2, le=2)
    is_active: bool = True
    description: str = Field(default="", max_length=2000)


class ModelConfigUpdate(BaseModel):
    model_type: Literal["chat", "embedding"] | None = None
    provider: Literal["openai", "openai_compatible", "anthropic", "auto"] | None = None
    api_base: str | None = Field(default=None, max_length=500)
    api_key: str | None = Field(default=None, max_length=10000, repr=False)
    model_name: str | None = Field(default=None, min_length=1, max_length=200)
    temperature: float | None = Field(default=None, ge=0, le=2)
    max_tokens: int | None = Field(default=None, ge=1, le=32768)
    top_p: float | None = Field(default=None, ge=0, le=1)
    frequency_penalty: float | None = Field(default=None, ge=-2, le=2)
    presence_penalty: float | None = Field(default=None, ge=-2, le=2)
    is_active: bool | None = None
    description: str | None = Field(default=None, max_length=2000)


class ModelConfig(BaseModel):
    """The redacted configuration returned to browsers and task views."""

    id: str
    model_type: Literal["chat", "embedding"]
    provider: Literal["openai", "openai_compatible", "anthropic", "auto"]
    api_base: str | None = None
    model_name: str
    temperature: float
    max_tokens: int
    top_p: float
    frequency_penalty: float
    presence_penalty: float
    is_active: bool
    description: str
    api_key_configured: bool = False
    created_at: datetime
    updated_at: datetime


class ModelConnectionCheck(BaseModel):
    """Redaction-safe result of a minimal local provider connectivity check."""

    config_id: str
    provider: str
    model_name: str
    status: Literal[
        "connected",
        "authentication_failed",
        "invalid_configuration",
        "timeout",
        "unavailable",
    ]
    message: str
    latency_ms: int | None = None
    checked_at: datetime


class StoredModelConfig(ModelConfig):
    """Internal record.  Credentials never appear in the public response model."""

    api_key: str = Field(repr=False)

    def public(self) -> ModelConfig:
        return ModelConfig(
            **self.model_dump(exclude={"api_key", "api_key_configured"}),
            api_key_configured=bool(self.api_key),
        )

    def runtime_options(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "api_key": self.api_key,
            "model_name": self.model_name,
            "api_base": self.api_base,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }


class AuditTaskStatus(str, Enum):
    """审计任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AuditTaskCreate(BaseModel):
    """创建审计任务请求"""
    project_id: str
    use_llm: bool = False
    output_format: str = "markdown"


class AuditTask(BaseModel):
    """审计任务"""
    id: str
    project_id: str
    status: AuditTaskStatus
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    findings_count: int = 0
    remediation_count: int = 0
    result: dict[str, Any] | None = None
    error: str | None = None
    # 创建参数随任务持久化：进程重启把运行中任务标记为 FAILED 后，
    # retry 端点据此按原参数重建任务（llm_config 不持久化，重试时重新解析）。
    use_llm: bool = False
    output_format: str = "markdown"


class AuditTaskSummary(BaseModel):
    """Compact task projection used by polling and history views."""

    id: str
    project_id: str
    status: AuditTaskStatus
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    findings_count: int = 0
    remediation_count: int = 0
    error: str | None = None


class Finding(BaseModel):
    """漏洞发现"""
    id: str
    task_id: str
    vulnerability_type: str
    severity: str
    confidence: float
    title: str
    file_path: str
    line_start: int
    line_end: int
    description: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    verification_status: str = "needs_evidence"
    verification_level: int = 1
    verification_predicate: str | None = None
    evidence_bundle: dict[str, Any] = Field(default_factory=lambda: {
        "items": [], "gaps": [], "level": 1, "artifact_refs": [],
    })
    validation_sessions: list[dict[str, Any]] = Field(default_factory=list)
    duplicate_count: int = 1
    duplicate_finding_ids: list[str] = Field(default_factory=list)
    source_task_ids: list[str] = Field(default_factory=list)
    deduplication_key: str | None = None
    review_priority_score: int = 0
    review_priority: str = "P3"
    updated_at: datetime | None = None


class ProjectFindingQueue(BaseModel):
    """Deduplicated review queue while raw task results remain persisted."""

    project_id: str
    task_id: str | None = None
    includes_history: bool = False
    raw_findings_count: int
    review_findings_count: int
    duplicate_findings_count: int
    findings: list[Finding]


class FindingVerificationStatus(str, Enum):
    """Terminal state recorded by a Harness-owned validation session."""

    VERIFIED = "verified"
    REJECTED = "rejected"
    NEEDS_EVIDENCE = "needs_evidence"


class ValidationCase(BaseModel):
    """A bounded control request used to support a validation conclusion."""

    label: str = Field(min_length=1, max_length=160)
    expected_status: int = Field(ge=100, le=599)
    observed_status: int = Field(ge=100, le=599)
    passed: bool
    summary: str = Field(min_length=1, max_length=1000)


class DynamicValidationEvidence(BaseModel):
    """Structured, redaction-safe evidence from a controlled runtime check."""

    method: str = Field(min_length=1, max_length=64)
    source: str = Field(min_length=1, max_length=160)
    outcome: str = Field(min_length=1, max_length=64)
    summary: str = Field(min_length=1, max_length=2000)
    candidate_case: ValidationCase
    positive_control: ValidationCase
    negative_control: ValidationCase
    artifact_ref: str | None = Field(default=None, max_length=500)
    captured_at: datetime = Field(default_factory=datetime.now)


class FindingValidationUpdate(BaseModel):
    """A verification result submitted by an authenticated Harness worker."""

    verification_status: FindingVerificationStatus
    verification_level: int = Field(ge=1, le=5)
    verification_predicate: str = Field(min_length=8, max_length=2000)
    evidence: DynamicValidationEvidence


class RemediationBundle(BaseModel):
    """整改包"""
    finding_id: str
    vulnerability_type: str
    title: str
    severity: str
    file_path: str
    line_start: int
    line_end: int
    ai_patch_prompt: str
    patch_strategy: str
    patch_constraints: list[dict[str, Any]]
    retest_plan: list[dict[str, Any]]
    acceptance_criteria: list[str]
    package_id: str | None = None
    verification_status: str = "needs_evidence"
    proposal_only: bool = True
    state: str = "draft"


class PluginInfo(BaseModel):
    """插件信息"""
    name: str
    version: str
    author: str
    description: str
    plugin_type: str
    enabled: bool = True


class VRTMBuildRequest(BaseModel):
    """Build or evolve a runtime threat model for a local project."""
    project_id: str
    declaration_path: str | None = None
    observations: list[dict[str, Any]] = Field(default_factory=list)
    baseline_snapshot_id: str | None = None
    persist: bool = True


# ========== 内存存储（生产环境应使用数据库） ==========

projects_db: dict[str, Project] = {}
audit_tasks_db: dict[str, AuditTask] = {}
findings_db: dict[str, list[Finding]] = {}
remediation_db: dict[str, list[RemediationBundle]] = {}
model_configs_db: dict[str, StoredModelConfig] = {}


def _default_state_store_path() -> Path:
    configured_path = os.getenv("VIBE_SEC_API_DB_PATH")
    if configured_path:
        return Path(configured_path)
    return Path(__file__).resolve().parents[1] / ".vibe-sec" / "api-state.sqlite3"


api_state_store = ApiStateStore(_default_state_store_path())


def reload_api_state() -> None:
    """Hydrate caches and close tasks interrupted by a previous process exit."""
    persisted = api_state_store.load_state()
    projects = {
        project.id: project
        for payload in persisted["projects"]
        for project in [Project.model_validate(payload)]
    }
    tasks = {
        task.id: task
        for payload in persisted["audit_tasks"]
        for task in [AuditTask.model_validate(payload)]
    }
    findings: dict[str, list[Finding]] = {}
    for row in persisted["findings"]:
        finding = Finding.model_validate(row["payload"])
        findings.setdefault(row["task_id"], []).append(finding)
    remediations: dict[str, list[RemediationBundle]] = {}
    for row in persisted["remediations"]:
        remediation = RemediationBundle.model_validate(row["payload"])
        remediations.setdefault(row["task_id"], []).append(remediation)
    model_configs = {
        config.id: config
        for payload in persisted["model_configs"]
        for config in [StoredModelConfig.model_validate(payload)]
    }

    projects_db.clear()
    projects_db.update(projects)
    audit_tasks_db.clear()
    audit_tasks_db.update(tasks)
    findings_db.clear()
    findings_db.update(findings)
    remediation_db.clear()
    remediation_db.update(remediations)
    model_configs_db.clear()
    model_configs_db.update(model_configs)

    # FastAPI BackgroundTasks are process-local.  They cannot survive a restart,
    # so retaining an in-flight state would permanently mislead the local UI.
    interrupted_at = datetime.now()
    for task in audit_tasks_db.values():
        if task.status not in {AuditTaskStatus.PENDING, AuditTaskStatus.RUNNING}:
            continue
        task.status = AuditTaskStatus.FAILED
        task.completed_at = interrupted_at
        task.error = (
            "Audit interrupted by a local API process restart before completion. "
            "Create a new audit task to retry."
        )
        api_state_store.save_audit_task(task)

    # Earlier API versions serialized an orchestration failure's partial data
    # and then labeled the task completed.  Correct that durable state so the
    # review queue never treats an incomplete audit as a valid result.
    for task in audit_tasks_db.values():
        if task.status != AuditTaskStatus.COMPLETED or not isinstance(task.result, dict):
            continue
        if "partial_results" not in task.result:
            continue
        task.status = AuditTaskStatus.FAILED
        task.error = (
            "Audit orchestration returned partial results instead of a completed review. "
            "Create a new audit task after resolving the reported runtime error."
        )
        api_state_store.save_audit_task(task)


def configure_state_store(database_path: str | Path | None = None) -> Path:
    """Switch storage explicitly, primarily for isolated integration tests."""
    global api_state_store

    replacement = ApiStateStore(database_path or _default_state_store_path())
    previous_store = api_state_store
    api_state_store = replacement
    previous_store.close()
    reload_api_state()
    return api_state_store.path


def clear_api_state() -> None:
    """Clear both the cache and durable records without removing the database file."""
    api_state_store.clear()
    projects_db.clear()
    audit_tasks_db.clear()
    findings_db.clear()
    remediation_db.clear()
    model_configs_db.clear()


reload_api_state()


def _finding_evidence_bundle(finding_data: dict[str, Any]) -> dict[str, Any]:
    """Keep the audit result's verification contract intact at the API boundary."""
    bundle = dict(finding_data.get("evidence_bundle") or {})
    bundle.setdefault("items", list(finding_data.get("evidence") or []))
    bundle.setdefault("gaps", list(finding_data.get("evidence_gaps") or []))
    bundle.setdefault(
        "level",
        finding_data.get("verification_level") or finding_data.get("evidence_level") or 1,
    )
    bundle.setdefault("artifact_refs", list(finding_data.get("artifact_refs") or []))
    return bundle


def _require_validation_token(presented_token: str | None) -> None:
    """Prevent an unauthenticated client from promoting a finding to verified."""
    configured_token = os.getenv("VIBE_SEC_VALIDATION_TOKEN")
    if not configured_token:
        raise HTTPException(
            status_code=503,
            detail="Validation writes are disabled until VIBE_SEC_VALIDATION_TOKEN is configured",
        )
    if not presented_token or not secrets.compare_digest(presented_token, configured_token):
        raise HTTPException(status_code=403, detail="Invalid validation token")


def _validation_supports_status(update: FindingValidationUpdate) -> bool:
    if update.verification_status == FindingVerificationStatus.NEEDS_EVIDENCE:
        return True
    controls = (
        update.evidence.candidate_case,
        update.evidence.positive_control,
        update.evidence.negative_control,
    )
    if not all(case.passed for case in controls):
        return False
    if update.verification_status == FindingVerificationStatus.VERIFIED:
        return (
            update.evidence.method in {"service", "browser", "sandbox"}
            and update.evidence.outcome == "supported"
        )
    if update.verification_status == FindingVerificationStatus.REJECTED:
        return update.evidence.outcome == "contradicted"
    return True


# ========== 项目 API ==========

@app.post("/api/projects", response_model=Project)
async def create_project(project: ProjectCreate):
    """创建项目"""
    project_id = str(uuid.uuid4())
    now = datetime.now()

    new_project = Project(
        id=project_id,
        name=project.name,
        path=project.path,
        description=project.description,
        audit_scope=project.audit_scope,
        created_at=now,
        updated_at=now,
    )

    projects_db[project_id] = new_project
    api_state_store.save_project(new_project)
    return new_project


@app.get("/api/projects", response_model=list[Project])
async def list_projects():
    """列出所有项目"""
    return list(projects_db.values())


@app.get("/api/projects/{project_id}", response_model=Project)
async def get_project(project_id: str):
    """获取项目详情"""
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")
    return projects_db[project_id]


@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: str):
    """删除项目"""
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")

    api_state_store.delete_project(project_id)
    del projects_db[project_id]
    return {"message": "Project deleted"}


def _save_model_config(config: StoredModelConfig) -> StoredModelConfig:
    """Persist a model and ensure a Chat audit has one unambiguous active model."""
    if config.model_type == "chat" and config.is_active:
        for config_id, existing in list(model_configs_db.items()):
            if config_id == config.id or existing.model_type != "chat" or not existing.is_active:
                continue
            inactive = existing.model_copy(update={"is_active": False, "updated_at": datetime.now()})
            model_configs_db[config_id] = inactive
            api_state_store.save_model_config(inactive)
    model_configs_db[config.id] = config
    api_state_store.save_model_config(config)
    return config


@app.get("/api/model-configs", response_model=list[ModelConfig])
async def list_model_configs(model_type: str | None = None):
    """List local model profiles without returning API credentials."""
    configs = sorted(model_configs_db.values(), key=lambda config: config.updated_at, reverse=True)
    if model_type:
        configs = [config for config in configs if config.model_type == model_type]
    return [config.public() for config in configs]


@app.get("/api/model-configs/{config_id}", response_model=ModelConfig)
async def get_model_config(config_id: str):
    config = model_configs_db.get(config_id)
    if not config:
        raise HTTPException(status_code=404, detail="Model configuration not found")
    return config.public()


def _model_connection_failure(exc: Exception) -> tuple[str, str]:
    status_code = getattr(exc, "status_code", None)
    if status_code in {401, 403}:
        return (
            "authentication_failed",
            "LLM provider authentication failed. Check the API key, API Base URL, and account access.",
        )
    if isinstance(exc, TimeoutError):
        return "timeout", "LLM provider did not respond before the local request timeout."
    if isinstance(exc, ValueError):
        return "invalid_configuration", "The local model configuration is invalid. Update the provider settings."
    return "unavailable", "LLM provider is unavailable. Check the endpoint and local network access."


@app.post("/api/model-configs/{config_id}/test-connection", response_model=ModelConnectionCheck)
async def test_model_config_connection(config_id: str):
    """Run one bounded provider request without exposing credentials or response text."""
    config = model_configs_db.get(config_id)
    if not config:
        raise HTTPException(status_code=404, detail="Model configuration not found")

    checked_at = datetime.now()
    started_at = asyncio.get_running_loop().time()
    try:
        service = create_configured_llm_service(**config.runtime_options())
        await service.chat(
            [LLMMessage(role="user", content="Reply with the single word READY.")],
            temperature=0,
            max_tokens=8,
        )
    except Exception as exc:
        status, message = _model_connection_failure(exc)
        return ModelConnectionCheck(
            config_id=config.id,
            provider=config.provider,
            model_name=config.model_name,
            status=status,
            message=message,
            latency_ms=round((asyncio.get_running_loop().time() - started_at) * 1000),
            checked_at=checked_at,
        )

    return ModelConnectionCheck(
        config_id=config.id,
        provider=config.provider,
        model_name=config.model_name,
        status="connected",
        message="LLM provider accepted the bounded connectivity check.",
        latency_ms=round((asyncio.get_running_loop().time() - started_at) * 1000),
        checked_at=checked_at,
    )


@app.post("/api/model-configs", response_model=ModelConfig, status_code=201)
async def create_model_config(config: ModelConfigCreate):
    now = datetime.now()
    try:
        api_key = normalize_llm_api_key(config.api_key)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    record = StoredModelConfig(
        id=str(uuid.uuid4()),
        model_type=config.model_type,
        provider=config.provider,
        api_base=str(config.api_base or "").strip() or None,
        api_key=api_key,
        model_name=config.model_name.strip(),
        temperature=config.temperature,
        max_tokens=config.max_tokens,
        top_p=config.top_p,
        frequency_penalty=config.frequency_penalty,
        presence_penalty=config.presence_penalty,
        is_active=config.is_active,
        description=config.description.strip(),
        created_at=now,
        updated_at=now,
    )
    if not record.api_key or not record.model_name:
        raise HTTPException(status_code=422, detail="API key and model name are required")
    return _save_model_config(record).public()


@app.put("/api/model-configs/{config_id}", response_model=ModelConfig)
async def update_model_config(config_id: str, update: ModelConfigUpdate):
    existing = model_configs_db.get(config_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Model configuration not found")

    changes = update.model_dump(exclude_unset=True)
    submitted_key = changes.pop("api_key", None)
    if submitted_key is not None and submitted_key.strip():
        try:
            changes["api_key"] = normalize_llm_api_key(submitted_key)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    if "api_base" in changes:
        changes["api_base"] = str(changes["api_base"] or "").strip() or None
    if "model_name" in changes:
        changes["model_name"] = str(changes["model_name"] or "").strip()
    if "description" in changes:
        changes["description"] = str(changes["description"] or "").strip()
    changes["updated_at"] = datetime.now()
    record = existing.model_copy(update=changes)
    if not record.api_key or not record.model_name:
        raise HTTPException(status_code=422, detail="API key and model name are required")
    return _save_model_config(record).public()


@app.put("/api/model-configs/{config_id}/activate", response_model=ModelConfig)
async def activate_model_config(config_id: str):
    existing = model_configs_db.get(config_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Model configuration not found")
    record = existing.model_copy(update={"is_active": True, "updated_at": datetime.now()})
    return _save_model_config(record).public()


@app.put("/api/model-configs/{config_id}/deactivate", response_model=ModelConfig)
async def deactivate_model_config(config_id: str):
    existing = model_configs_db.get(config_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Model configuration not found")
    record = existing.model_copy(update={"is_active": False, "updated_at": datetime.now()})
    return _save_model_config(record).public()


@app.delete("/api/model-configs/{config_id}")
async def delete_model_config(config_id: str):
    if config_id not in model_configs_db:
        raise HTTPException(status_code=404, detail="Model configuration not found")
    api_state_store.delete_model_config(config_id)
    del model_configs_db[config_id]
    return {"message": "Model configuration deleted"}


# ========== 审计任务 API ==========

def _active_chat_model_config() -> StoredModelConfig | None:
    active_configs = [
        config for config in model_configs_db.values()
        if config.model_type == "chat" and config.is_active and config.api_key
    ]
    if not active_configs:
        return None
    return max(active_configs, key=lambda config: config.updated_at)


def _legacy_llm_key_is_configured() -> bool:
    return bool(
        os.getenv("VIBE_SEC_DEEPSEEK_API_KEY")
        or os.getenv("DEEPSEEK_API_KEY")
    )


def _resolve_llm_config_or_raise(use_llm: bool) -> dict[str, Any] | None:
    """创建/重试任务共用的 LLM 配置解析：未就绪时以 422 拒绝。"""
    if not use_llm:
        return None
    active_config = _active_chat_model_config()
    if active_config:
        if active_config.provider in {"openai_compatible", "auto"} and not active_config.api_base:
            raise HTTPException(
                status_code=422,
                detail="The active OpenAI-compatible model needs an API Base URL",
            )
        return active_config.runtime_options()
    if not _legacy_llm_key_is_configured():
        raise HTTPException(
            status_code=422,
            detail=(
                "LLM review needs an active Chat model with an API key. "
                "Configure one in Settings > Models, then retry."
            ),
        )
    return None


def _execute_audit(
    project: Project,
    use_llm: bool,
    output_format: str,
    llm_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the audit in a worker thread without blocking FastAPI's event loop."""
    from main import run_audit

    return asyncio.run(run_audit(
        project_path=project.path,
        audit_scope={
            "web_vulns": project.audit_scope.web_vulns,
            "agent_vulns": project.audit_scope.agent_vulns,
            "secret_leaks": project.audit_scope.secret_leaks,
        },
        output_format=output_format,
        use_llm=use_llm,
        llm_config=llm_config,
        # A completed audit is also the latest source-grounded runtime model.
        # Persist it so the threat-model view works without a second manual run.
        persist_vrtm=True,
    ))


async def run_audit_task(
    task_id: str,
    project: Project,
    use_llm: bool,
    output_format: str,
    llm_config: dict[str, Any] | None = None,
):
    """后台运行审计任务"""
    task = audit_tasks_db[task_id]
    task.status = AuditTaskStatus.RUNNING
    task.started_at = datetime.now()
    api_state_store.save_audit_task(task)

    try:
        result = await asyncio.to_thread(
            _execute_audit,
            project,
            use_llm,
            output_format,
            llm_config,
        )

        # 保存结果
        task.result = result
        task.findings_count = len(result.get("findings", []))
        task.remediation_count = len(result.get("remediation_bundles", []))
        task.status = AuditTaskStatus.COMPLETED
        task.completed_at = datetime.now()

        # 保存 findings
        findings = []
        for finding_data in result.get("findings", []):
            evidence_bundle = _finding_evidence_bundle(finding_data)
            finding = Finding(
                id=finding_data.get("id", str(uuid.uuid4())),
                task_id=task_id,
                vulnerability_type=finding_data.get("vulnerability_type", "unknown"),
                severity=finding_data.get("severity", "medium"),
                confidence=finding_data.get("confidence", 0.5),
                title=finding_data.get("title", "Unknown"),
                file_path=finding_data.get("file_path", ""),
                line_start=finding_data.get("line_start", 0),
                line_end=finding_data.get("line_end", 0),
                description=finding_data.get("description", ""),
                evidence=list(finding_data.get("evidence", []) or []),
                verification_status=finding_data.get("verification_status", "needs_evidence"),
                verification_level=int(evidence_bundle.get("level") or 1),
                verification_predicate=finding_data.get("verification_predicate"),
                evidence_bundle=evidence_bundle,
                validation_sessions=list(finding_data.get("validation_sessions", []) or []),
                duplicate_count=int(finding_data.get("duplicate_count") or 1),
                duplicate_finding_ids=list(finding_data.get("duplicate_finding_ids", []) or []),
                source_task_ids=list(finding_data.get("source_task_ids", []) or []),
                deduplication_key=finding_data.get("deduplication_key"),
                review_priority_score=int(finding_data.get("review_priority_score") or 0),
                review_priority=str(finding_data.get("review_priority") or "P3"),
                updated_at=datetime.now(),
            )
            findings.append(finding)

        findings_db[task_id] = findings

        # 保存 remediation bundles
        remediation_bundles = []
        for bundle_data in result.get("remediation_bundles", []):
            verification_status = str(bundle_data.get("verification_status", "needs_evidence"))
            metadata = dict(bundle_data.get("metadata") or {})
            bundle = RemediationBundle(
                finding_id=bundle_data.get("finding_id", ""),
                vulnerability_type=bundle_data.get("vulnerability_type", "unknown"),
                title=bundle_data.get("title", "Unknown"),
                severity=bundle_data.get("severity", "medium"),
                file_path=bundle_data.get("file_path", ""),
                line_start=bundle_data.get("line_start", 0),
                line_end=bundle_data.get("line_end", 0),
                ai_patch_prompt=bundle_data.get("ai_patch_prompt", ""),
                patch_strategy=bundle_data.get("patch_strategy", "unknown"),
                patch_constraints=bundle_data.get("patch_constraints", []),
                retest_plan=bundle_data.get("retest_plan", []),
                acceptance_criteria=bundle_data.get("acceptance_criteria", []),
                package_id=bundle_data.get("package_id"),
                verification_status=verification_status,
                proposal_only=bool(metadata.get("proposal_only", verification_status != "verified")),
                state=str(bundle_data.get("state", "draft")),
            )
            remediation_bundles.append(bundle)

        remediation_db[task_id] = remediation_bundles
        api_state_store.replace_task_results(task, findings, remediation_bundles)

    except Exception as e:
        task.status = AuditTaskStatus.FAILED
        task.error = str(e)
        task.completed_at = datetime.now()
        api_state_store.save_audit_task(task)


@app.post("/api/audit-tasks", response_model=AuditTask)
async def create_audit_task(
    task: AuditTaskCreate,
    background_tasks: BackgroundTasks,
):
    """创建审计任务"""
    if task.project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")

    task_id = str(uuid.uuid4())
    project = projects_db[task.project_id]
    llm_config = _resolve_llm_config_or_raise(task.use_llm)

    new_task = AuditTask(
        id=task_id,
        project_id=task.project_id,
        status=AuditTaskStatus.PENDING,
        created_at=datetime.now(),
        use_llm=task.use_llm,
        output_format=task.output_format,
    )

    audit_tasks_db[task_id] = new_task
    api_state_store.save_audit_task(new_task)

    # 后台运行审计任务
    background_tasks.add_task(
        run_audit_task,
        task_id,
        project,
        task.use_llm,
        task.output_format,
        llm_config,
    )

    return new_task


@app.post("/api/audit-tasks/{task_id}/retry", response_model=AuditTask)
async def retry_audit_task(task_id: str, background_tasks: BackgroundTasks):
    """按原参数重试失败/被重启中断的审计任务，返回新的 PENDING 任务。

    进程重启会把运行中任务标记为 FAILED（见状态加载逻辑）；本端点把
    "手动新建任务"缩短为一键重试，llm_config 按当前激活模型重新解析。
    """
    original = audit_tasks_db.get(task_id)
    if original is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if original.status != AuditTaskStatus.FAILED:
        raise HTTPException(
            status_code=409,
            detail="Only failed or restart-interrupted audit tasks can be retried",
        )
    if original.project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")

    llm_config = _resolve_llm_config_or_raise(original.use_llm)
    new_task = AuditTask(
        id=str(uuid.uuid4()),
        project_id=original.project_id,
        status=AuditTaskStatus.PENDING,
        created_at=datetime.now(),
        use_llm=original.use_llm,
        output_format=original.output_format,
    )
    audit_tasks_db[new_task.id] = new_task
    api_state_store.save_audit_task(new_task)
    background_tasks.add_task(
        run_audit_task,
        new_task.id,
        projects_db[original.project_id],
        new_task.use_llm,
        new_task.output_format,
        llm_config,
    )
    return new_task


@app.get("/api/audit-tasks", response_model=list[AuditTaskSummary])
async def list_audit_tasks(project_id: str | None = None):
    """列出审计任务"""
    if project_id:
        return [t for t in audit_tasks_db.values() if t.project_id == project_id]
    return list(audit_tasks_db.values())


@app.get("/api/audit-tasks/{task_id}", response_model=AuditTask)
async def get_audit_task(task_id: str):
    """获取审计任务详情"""
    if task_id not in audit_tasks_db:
        raise HTTPException(status_code=404, detail="Task not found")
    return audit_tasks_db[task_id]


# ========== 结果查询 API ==========

@app.get("/api/audit-tasks/{task_id}/findings", response_model=list[Finding])
async def get_findings(task_id: str):
    """获取审计发现"""
    if task_id not in audit_tasks_db:
        raise HTTPException(status_code=404, detail="Task not found")
    return findings_db.get(task_id, [])


@app.get("/api/projects/{project_id}/findings", response_model=ProjectFindingQueue)
async def get_project_finding_queue(project_id: str, include_history: bool = False):
    """Return the latest review queue, or an explicit cross-task historical queue."""
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")
    completed_tasks = sorted(
        (
            task for task in audit_tasks_db.values()
            if task.project_id == project_id and task.status == AuditTaskStatus.COMPLETED
        ),
        key=lambda task: task.completed_at or task.created_at,
        reverse=True,
    )
    source_tasks = completed_tasks if include_history else completed_tasks[:1]
    raw = [
        finding.model_dump(mode="json")
        for task in source_tasks
        for finding in findings_db.get(task.id, [])
    ]
    clusters = cluster_findings(raw)
    return ProjectFindingQueue(
        project_id=project_id,
        task_id=None if include_history or not source_tasks else source_tasks[0].id,
        includes_history=include_history,
        raw_findings_count=len(raw),
        review_findings_count=len(clusters),
        duplicate_findings_count=max(0, len(raw) - len(clusters)),
        findings=[Finding.model_validate(item) for item in clusters],
    )


@app.post(
    "/api/audit-tasks/{task_id}/findings/{finding_id}/validation",
    response_model=Finding,
)
async def record_finding_validation(
    task_id: str,
    finding_id: str,
    update: FindingValidationUpdate,
    x_vibe_sec_validation_token: str | None = Header(default=None),
):
    """Record a Harness-authenticated runtime validation without trusting a bare claim."""
    _require_validation_token(x_vibe_sec_validation_token)
    if task_id not in audit_tasks_db:
        raise HTTPException(status_code=404, detail="Task not found")
    if audit_tasks_db[task_id].status != AuditTaskStatus.COMPLETED:
        raise HTTPException(status_code=409, detail="Validation requires a completed audit task")
    finding = next((item for item in findings_db.get(task_id, []) if item.id == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not _validation_supports_status(update):
        raise HTTPException(
            status_code=422,
            detail="Verification status is not supported by the submitted controls and evidence",
        )

    session = update.evidence.model_dump(mode="json")
    session["id"] = f"validation-{uuid.uuid4().hex[:16]}"
    session["verification_status"] = update.verification_status.value
    session["verification_level"] = update.verification_level
    session["verification_predicate"] = update.verification_predicate
    finding.validation_sessions.append(session)
    finding.evidence.append({
        "id": session["id"],
        "type": update.evidence.method,
        "source": update.evidence.source,
        "summary": update.evidence.summary,
        "outcome": update.evidence.outcome,
        "captured_at": update.evidence.captured_at.isoformat(),
        "artifact_ref": update.evidence.artifact_ref,
    })
    bundle = dict(finding.evidence_bundle)
    bundle["items"] = [*list(bundle.get("items") or []), session]
    bundle["level"] = update.verification_level
    if update.verification_status == FindingVerificationStatus.NEEDS_EVIDENCE:
        bundle["gaps"] = list(bundle.get("gaps") or [])
    else:
        bundle["gaps"] = []
    finding.evidence_bundle = bundle
    finding.verification_status = update.verification_status.value
    finding.verification_level = update.verification_level
    finding.verification_predicate = update.verification_predicate
    finding.updated_at = datetime.now()
    api_state_store.save_finding(finding)
    return finding


@app.get("/api/audit-tasks/{task_id}/remediations", response_model=list[RemediationBundle])
async def get_remediations(task_id: str):
    """获取整改包"""
    if task_id not in audit_tasks_db:
        raise HTTPException(status_code=404, detail="Task not found")
    findings_by_id = {finding.id: finding for finding in findings_db.get(task_id, [])}
    bundles = []
    for bundle in remediation_db.get(task_id, []):
        finding = findings_by_id.get(bundle.finding_id)
        verification_status = finding.verification_status if finding else bundle.verification_status
        bundles.append(bundle.model_copy(update={
            "verification_status": verification_status,
            "proposal_only": verification_status != "verified",
        }))
    return bundles


# ========== 插件管理 API ==========

@app.get("/api/plugins", response_model=list[PluginInfo])
async def list_plugins():
    """列出所有插件"""
    from core.plugin import plugin_registry

    plugins = []
    for name in plugin_registry.list_plugins():
        plugin = plugin_registry.get_plugin(name)
        if plugin:
            plugins.append(PluginInfo(
                name=plugin.metadata.name,
                version=plugin.metadata.version,
                author=plugin.metadata.author,
                description=plugin.metadata.description,
                plugin_type=plugin.metadata.plugin_type.value,
            ))

    return plugins


# ========== VRTM API ==========

@app.post("/api/vrtm/models")
async def build_vrtm_model(request: VRTMBuildRequest):
    from core.vrtm import VRTMModelStore, VRTMService

    try:
        if request.project_id not in projects_db:
            raise HTTPException(status_code=404, detail="Project not found")
        project_path = projects_db[request.project_id].path
        declaration_path = None
        if request.declaration_path:
            root = Path(project_path).resolve()
            declaration = Path(request.declaration_path)
            declaration = declaration.resolve() if declaration.is_absolute() else (root / declaration).resolve()
            try:
                declaration.relative_to(root)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="Declaration path escapes project root") from exc
            declaration_path = str(declaration)
        store = VRTMModelStore(project_path)
        previous = store.load(request.baseline_snapshot_id) if request.baseline_snapshot_id else None
        return await VRTMService(project_path).build(
            declaration_path=declaration_path,
            observations=request.observations,
            previous_result=previous,
            persist=request.persist,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/vrtm/models/latest")
async def get_latest_vrtm_model(project_id: str):
    from core.harness.models import RuntimeSurfaceGraph
    from core.vrtm import VRTMModelStore

    try:
        if project_id not in projects_db:
            raise HTTPException(status_code=404, detail="Project not found")
        result = VRTMModelStore(projects_db[project_id].path).load_latest()
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="No VRTM model has been stored for this project")
    # Older snapshots contain the full source graph but predate semantic
    # projections. Migrate only the visualization layer so existing evidence,
    # findings, and model fingerprints remain unchanged.
    visualization = (result.get("graph") or {}).get("visualization") or {}
    if "projections" not in visualization:
        try:
            graph_data = dict(result.get("graph") or {})
            graph = RuntimeSurfaceGraph.from_dict(graph_data)
            graph_data["visualization"] = graph.to_visualization(result.get("threat_model") or {})
            result = dict(result)
            result["graph"] = graph_data
            VRTMModelStore(projects_db[project_id].path).save(result)
        except (KeyError, TypeError, ValueError, OSError):
            # A legacy or partially written snapshot is still useful in source
            # trace mode; do not make model history unavailable for a UI upgrade.
            pass
    return result


@app.get("/api/vrtm/models")
async def list_vrtm_models(project_id: str):
    from core.vrtm import VRTMModelStore

    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"snapshots": VRTMModelStore(projects_db[project_id].path).list_snapshots()}


# ========== 系统信息 API ==========

@app.get("/api/health")
async def health_check():
    """健康检查"""
    return {
        "status": "healthy",
        "version": "0.5.0",
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/api/stats")
async def get_stats():
    """获取系统统计"""
    from core.cache import cache

    return {
        "projects_count": len(projects_db),
        "tasks_count": len(audit_tasks_db),
        "completed_tasks": len([t for t in audit_tasks_db.values() if t.status == AuditTaskStatus.COMPLETED]),
        "total_findings": sum(t.findings_count for t in audit_tasks_db.values()),
        "cache_stats": cache.get_stats(),
    }


# ========== 启动服务 ==========

def start_server(host: str = "127.0.0.1", port: int = 8000):
    """启动 API 服务器"""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_server()
