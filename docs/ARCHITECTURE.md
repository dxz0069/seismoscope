# Vibe Sec Platform 架构文档

## 概述

Vibe Sec Platform 是一个面向 Vibe Coding 范式的安全审查验证平台，采用多层架构设计，支持插件扩展和多种接入方式。

## 架构概览

```
┌──────────────────────────────────────────────────────────────────────┐
│                         接入层 (Integration Layer)                    │
│  Claude Code Skill / CLI / REST API / Web UI (可选)                  │
└──────────────────────────────────────────────────────────────────────┘
                                    ↓
┌──────────────────────────────────────────────────────────────────────┐
│                         编排层 (Orchestration Layer)                  │
│  Deterministic Orchestrator                                          │
│  Plan → Recon → Surface → Audit → Merge → Verify → Remediate        │
└──────────────────────────────────────────────────────────────────────┘
                                    ↓
┌──────────────────────────────────────────────────────────────────────┐
│                         智能体层 (Agent Layer)                        │
│  ReconAgent / SurfaceAgent / AuditAgent / VerificationAgent         │
│  RemediationAgent / RegressionAgent                                  │
└──────────────────────────────────────────────────────────────────────┘
                                    ↓
┌──────────────────────────────────────────────────────────────────────┐
│                         能力层 (Capability Layer)                     │
│  RuntimeSurface / RiskChain / VerificationHarness / Skill KB        │
│  PermissionPolicy / ReasoningGuard / Cache / Plugin System          │
└──────────────────────────────────────────────────────────────────────┘
                                    ↓
┌──────────────────────────────────────────────────────────────────────┐
│                         基础设施层 (Infrastructure Layer)             │
│  ToolRuntime / SessionStore / EvidenceArchive / FindingStore        │
│  OutputFormatter / PluginRegistry                                    │
└──────────────────────────────────────────────────────────────────────┘
```

## 核心组件

### 1. 编排器 (Orchestrator)

**文件**: `core/orchestrator/orchestrator.py`

**职责**:
- 执行确定性审查流程
- 协调多个 Agent 按顺序工作
- 管理状态转换和数据传递
- 处理异常和重试

**设计原则**:
- **确定性优先**: 不让 LLM 决定主要阶段
- **结构化交接**: Agent 间通过 TaskHandoff 传递上下文
- **阶段门控**: 每个阶段必须成功才能进入下一阶段

**执行流程**:
```
1. Recon (信息收集)
   ↓
2. Surface (攻击面建模)
   ↓
3. Audit (漏洞审查，可并行)
   ↓
4. Merge (合并发现)
   ↓
5. Verification (漏洞验证)
   ↓
6. Remediation (整改建议)
   ↓
7. Regression (回归测试，可选)
```

### 2. 智能体 (Agents)

**目录**: `agents/`

#### ReconAgent
- **职责**: 信息收集
- **输入**: 项目路径
- **输出**: 技术栈、文件结构、入口点、依赖关系
- **模式**: ReAct

#### SurfaceAgent
- **职责**: 攻击面建模
- **输入**: Recon 数据
- **输出**: RuntimeSurface（攻击面画像）
- **关键能力**: 识别入口点、工具、权限、信任边界

#### AuditAgent
- **职责**: 漏洞审查
- **输入**: RuntimeSurface
- **输出**: 候选 Findings
- **支持漏洞类型**:
  - Web 漏洞: SQL 注入、XSS、命令注入、路径遍历等
  - Agent 漏洞: 提示词注入、MCP 风险、过度代理等
  - 密钥泄露: 硬编码密码、API Key 等

#### VerificationAgent
- **职责**: 漏洞验证
- **输入**: 候选 Findings
- **输出**: 验证后的 Findings
- **验证方式**: 静态分析 + 动态执行 + Fuzzing

#### RemediationAgent
- **职责**: 整改建议生成
- **输入**: 验证后的 Findings
- **输出**: RemediationBundle（整改包）
- **包含内容**: ai_patch_prompt、patch_constraints、retest_plan、acceptance_criteria

#### RegressionAgent
- **职责**: 回归测试
- **输入**: 整改包
- **输出**: 回归测试报告
- **测试内容**: 漏洞修复验证、功能完整性、副作用检测

### 3. 攻击面分析 (Surface Analysis)

**目录**: `core/surface/`

#### RuntimeSurface
- **文件**: `runtime_surface.py`
- **职责**: 构建应用的运行面画像
- **包含**: 页面入口、Prompt 配置、工具画像、权限画像、信任边界、代码块索引

#### RiskChain
- **文件**: `risk_chain.py`
- **职责**: 将孤立的 finding 串联为完整的攻击路径
- **包含**: source_signal、preconditions、boundary_path、impact_hypothesis、evidence_predicates

### 4. 安全控制 (Security Controls)

**目录**: `core/runtime/`, `core/reasoning/`

#### PermissionPolicy
- **文件**: `core/runtime/permission_policy.py`
- **职责**: 基于 deny-list 的权限检查
- **检查项**: 工具名黑名单、工具名前缀黑名单、域名白名单、关键动作黑名单

#### ReasoningGuard
- **文件**: `core/reasoning/reasoning_guard.py`
- **职责**: 防止 Agent 推理偏差
- **检测异常**: unsupported_confirmation、evidence_mismatch、reward_hacking_risk、closure_state_conflict

### 5. 验证系统 (Verification)

**目录**: `core/verification/`

**验证方式**:
- **静态分析**: 模式匹配、污点分析、数据流分析
- **动态执行**: Docker 沙箱、本地测试环境
- **Fuzzing**: 模糊测试、变异测试
- **浏览器证据**: Playwright 截图、DOM 快照、网络日志

### 6. 整改系统 (Remediation)

**目录**: `core/remediation/`

#### RemediationBundle
- **文件**: `remediation_bundle.py`
- **职责**: 生成整改建议包
- **包含**: ai_patch_prompt、patch_constraints、retest_plan、acceptance_criteria

#### Skill Relay
- **文件**: `skill_relay.py`
- **职责**: 追踪整改包流转
- **状态机**: draft → dispatched → acknowledged → in_progress → completed → returned

### 7. 插件系统 (Plugin System)

**目录**: `core/plugin/`, `plugins/`

**插件类型**:
- **DetectionRulePlugin**: 自定义漏洞检测规则
- **ReportFormatPlugin**: 自定义报告格式
- **VerificationPlugin**: 自定义验证方式
- **RemediationPlugin**: 自定义修复策略

**插件加载**:
- 从文件加载: `plugin_loader.load_from_file()`
- 从目录加载: `plugin_loader.load_from_directory()`

### 8. 缓存系统 (Cache)

**文件**: `core/cache.py`

**缓存层级**:
- **内存缓存**: 快速访问，默认 TTL 1 小时
- **文件缓存**: 持久化存储，默认 TTL 24 小时
- **多级缓存**: 先查内存，再查文件

**缓存策略**:
- 项目扫描缓存
- 漏洞模式缓存
- LLM 调用缓存
- 结果缓存

### 9. 输出格式化 (Output Formatting)

**文件**: `core/reporting/output_formatter.py`

**支持格式**:
- **Markdown**: 人类可读的报告
- **JSON**: 结构化数据
- **Claude Code**: Claude Code 原生格式
- **HTML**: 网页报告

### 10. REST API

**目录**: `api/`

**端点**:
- `/api/projects`: 项目管理
- `/api/audit-tasks`: 审计任务管理
- `/api/findings`: 结果查询
- `/api/plugins`: 插件管理
- `/api/health`: 健康检查

**文档**: Swagger UI (`/docs`), ReDoc (`/redoc`)

## 数据流

### 审查流程数据流

```
Project
  ↓
ReconAgent
  ↓ (tech_stack, entry_points)
SurfaceAgent
  ↓ (RuntimeSurface)
AuditAgent
  ↓ (candidate_findings)
Merge
  ↓ (merged_findings)
VerificationAgent
  ↓ (verified_findings)
RemediationAgent
  ↓ (remediation_bundles)
RegressionAgent
  ↓ (regression_reports)
Final Report
```

### TaskHandoff 数据结构

```python
TaskHandoff(
    from_agent="audit",
    to_agent="verification",
    summary="Found 15 vulnerabilities",
    key_findings=[...],
    insights=[...],
    context_refs={...},
    confidence=0.85,
)
```

## 扩展性设计

### 插件扩展

通过插件系统可以轻松添加：
- 新的漏洞检测规则
- 新的报告格式
- 新的验证方式
- 新的修复策略

### 自定义 Agent

可以创建自定义 Agent 处理特定类型的审查任务：
- 继承 `BaseAgent`
- 实现 `run()` 方法
- 注册到 `AgentRegistry`

### 自定义输出格式

通过 `ReportFormatPlugin` 实现自定义报告格式：
- 继承 `ReportFormatPlugin`
- 实现 `format()` 方法
- 注册到 `plugin_registry`

## 性能优化

### 并行执行

- AuditAgent 支持并行扫描多个漏洞类型
- 多语言项目可以并行分析

### 缓存策略

- 项目扫描结果缓存
- LLM 调用结果缓存
- 漏洞模式匹配缓存

### 资源管理

- Agent 超时控制
- 内存使用限制
- 文件句柄管理

## 安全考虑

### 沙箱执行

- 动态验证在 Docker 沙箱中执行
- 限制文件系统和网络访问
- 防止恶意代码执行

### 权限控制

- PermissionPolicy 控制工具调用
- ReasoningGuard 防止推理偏差
- 输入验证和净化

### 数据保护

- 敏感信息不写入日志
- 凭据使用环境变量
- API Key 安全存储

## 部署架构

### 单机部署

```
vibe-sec-platform/
├── api/server.py          # REST API 服务
├── main.py                # CLI 入口
└── skill/SKILL.md         # Claude Code Skill
```

### 分布式部署（规划中）

```
┌─────────────┐
│  API Server │
└──────┬──────┘
       ↓
┌─────────────┐
│ Orchestrator│
└──────┬──────┘
       ↓
┌─────────────────────────────┐
│  Agent Workers (多个实例)    │
└─────────────────────────────┘
       ↓
┌─────────────┐
│  Database   │
└─────────────┘
```

## 技术栈

- **语言**: Python 3.11+
- **Web 框架**: FastAPI
- **LLM**: OpenAI / Anthropic Claude
- **浏览器自动化**: Playwright
- **容器化**: Docker
- **测试**: pytest
- **文档**: Markdown, Swagger

## 版本历史

- **v0.1.0**: Phase 1 - MVP（基础审查流程）
- **v0.2.0**: Phase 2 - 增强验证（RuntimeSurface, RiskChain）
- **v0.3.0**: Phase 3 - Agent 漏洞审查（提示词注入、MCP 安全）
- **v0.4.0**: Phase 4 - 整改闭环（RemediationAgent, RegressionAgent）
- **v0.5.0**: Phase 5 - 优化与扩展（插件系统、缓存、REST API）

## 未来规划

- **v0.6.0**: Web UI 界面
- **v0.7.0**: 分布式部署支持
- **v0.8.0**: 插件市场
- **v1.0.0**: 稳定版本，生产环境就绪
