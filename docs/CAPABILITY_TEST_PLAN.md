# Vibe Sec Platform — 四维能力测试计划

## 测试概览

| 维度 | 焦点 | 方法 |
|------|------|------|
| D1 实际项目审计 | 平台能否在真实项目中发现真实漏洞？ | 多项目审计基准测试 |
| D2 横向对比 | 相比 AutoCVE / bandit / semgrep，差异在哪里？ | 同数据集的对照实验 |
| D3 工作流嵌入 | 实际嵌入开发流程是否顺畅？ | 端到端使用体验分析 |
| D4 建模方法论 | RuntimeSurface / RiskChain / VRTM 是否可用且正确？ | 方法论审查与边界测试 |

---

## D1：实际项目审计与测试

### 1.1 测试对象

| 层级 | 目标 | 预期发现 |
|------|------|---------|
| L0 基线 | `tests/fixtures/vulnerable_app.py`（已知 5 个 Web 漏洞） | SQL 注入、XSS、命令注入、路径遍历、eval 注入 |
| L0 基线 | `tests/fixtures/vulnerable_agent_app.py`（已知 7 类 Agent 漏洞） | 提示词注入、MCP 不安全、过度代理、密钥泄露、工具投毒、无限循环、上下文操纵 |
| L1 自审计 | **vibe-sec-platform 自身代码** (~34K 行 Python) | 硬编码密钥、不安全导入、缺失输入验证 |
| L2 真实 OSS | 选择一个小型开源 Flask/FastAPI 项目 | 真实 Web 漏洞 |
| L3 真实 Agent | 选择一个开源 AI Agent 项目 | Agent 特有漏洞 |

### 1.2 度量指标

```
检测率 (Recall)      = TP / (TP + FN)
精确率 (Precision)   = TP / (TP + FP)
F1 Score            = 2 * P * R / (P + R)
误报分析             = 每个 FP 的根因
漏报分析             = 每个 FN 的根因
```

### 1.3 L1 自审计执行步骤

```bash
# 1. 对平台自身运行审计（dogfooding）
python -m main audit . --format markdown --output audit-self.md

# 2. 验证检测结果
python -m pytest tests/ -v --tb=short

# 3. 运行代码质量检查
pip install ruff mypy
ruff check . --select E,F,W,B,S --ignore S101
mypy core/ agents/ --ignore-missing-imports
```

### 1.4 L1 关键检查项

- [ ] 检测到自身代码中的安全异味（如 `main.py` 中的环境变量处理）
- [ ] 检测到 `core/` 中可能的沙箱逃逸路径
- [ ] 检测到 `tests/fixtures/` 中的密钥暴露
- [ ] `RuntimeSurfaceBuilder` 对自身代码的建模是否准确
- [ ] 无 False Positive（平台不应标记 safe_login() 等安全代码）

### 1.5 L2/L3 真实项目测试设计

选取标准：
- Star > 500 的开源项目
- 包含已知 CVE 或安全公告（可以作为 ground truth）
- 优先选择 Flask / FastAPI / LangChain 项目

---

## D2：与 AutoCVE 及传统工具的横向对比

### 2.1 架构理念对比

| 维度 | vibe-sec-platform | AutoCVE | bandit | semgrep |
|------|------------------|---------|--------|---------|
| 编排方式 | 确定性编排器（7 阶段） | 确定性 Orchestrator + FindingAgent 队列 | 单次扫描 | 规则匹配 + 数据流 |
| Agent 架构 | 6 个专用 Agent + TaskHandoff | Multi-Agent + Nudge 纠偏 | 无 | 无 |
| 攻击面建模 | RuntimeSurface + RiskChain + VRTM | N/A | N/A | 部分（数据流图） |
| Agent 漏洞 | 支持（OWASP LLM Top 10） | 部分支持 | 不支持 | 不支持 |
| 验证机制 | 静态+动态+Fuzzing+浏览器 | Fuzzing Harness | 仅静态 | 仅静态 |
| 整改闭环 | RemediationBundle + Skill Relay | FindingAgent 终止 | 无 | 无 |
| 输出格式 | Markdown/JSON/Claude Code/HTML | 结构化 JSON | 纯文本 | JSON/SARIF |
| 接入方式 | Skill + CLI + REST API | CLI + API | CLI | CLI/CI/GitHub |

### 2.2 能力覆盖维度对比

```
                    vibe-sec    AutoCVE    bandit    semgrep
Web 漏洞检测          ✅          ⚠️         ✅        ✅
Agent 漏洞检测        ✅          ⚠️         ❌        ❌
MCP 安全审计          ✅          ❌         ❌        ❌
密钥泄露检测          ✅          ✅         ✅        ✅
攻击面建模            ✅          ❌         ❌        ⚠️
风险链分析            ✅          ❌         ❌        ❌
动态验证              ✅          ✅         ❌        ❌
浏览器证据            ✅          ❌         ❌        ❌
AI 驱动审查           ✅          ✅         ❌        ❌
并行审计通道          ✅          ✅         ❌        ⚠️
整改建议生成           ✅          ⚠️         ❌        ❌
回归测试              ✅          ❌         ❌        ❌
CI/CD 集成            ⚠️          ✅         ✅        ✅
```

### 2.3 对照实验设计

在 `tests/fixtures/vulnerable_app.py` 上运行三组工具：

| 工具 | 命令 | 预期检测数 |
|------|------|-----------|
| vibe-sec | `python -m main audit tests/fixtures --format json` | 15+ (含 Agent) |
| bandit | `bandit -r tests/fixtures/ -f json` | 3-5 (仅 Web) |
| semgrep | `semgrep --config auto tests/fixtures/` | 4-7 (仅 Web) |

对比维度：
1. **检测数量与种类**：vibe-sec 应覆盖 Agent 漏洞（独有能力）
2. **误报率**：bandit 的 `subprocess` 检测可能误报
3. **报告可用性**：vibe-sec 提供 RiskChain + 修复建议，bandit/semgrep 只有行号
4. **执行时间**：vibe-sec 的 7 阶段流程 vs bandit 的单次扫描

### 2.4 AutoCVE 对比详细分析

**共同借鉴的设计模式：**
- 确定性 Orchestrator（vibe-sec 简化了更多阶段）
- TaskHandoff 结构化交接（vibe-sec 添加了字符限制防溢出）
- FindingAgent 候选队列状态机（vibe-sec 用 CandidateStatus 枚举）
- Nudge 纠偏机制（vibe-sec 用 ReasoningGuard 替代）
- Skill 渐进式披露（两者相同）

**vibe-sec 独有的设计：**
- **RuntimeSurface**：AutoCVE 没有正式的攻击面建模
- **RiskChain**：AutoCVE 没有风险链概念
- **VRTM**：版本化运行时威胁模型是 vibe-sec 原创
- **Skill Relay 状态机**：整改包追踪（draft → completed → returned）
- **ClosurePolicy**：闭包策略评估
- **多 Agent 并行**：TaskGraphController 允许 Audit/Verification 通道并行

**AutoCVE 可能有优势的方面：**
- 更成熟的容器化部署
- CI/CD 集成更完善
- 分布式 Worker 支持

---

## D3：工作流嵌入开发流程的便捷性与可用性

### 3.1 三种接入方式的可用性评估

#### A. Claude Code Skill 方式

**评估项：**
- [ ] `skill/SKILL.md` 的定义是否完整、清晰？
- [ ] Installation Gate 流程是否无摩擦？（doctor → setup → doctor）
- [ ] `skill-audit --suggest-only` 的触发建议是否合理？
- [ ] `returned_packages` 结构的 `ai_patch_prompt` 是否能被 coding agent 直接使用？
- [ ] Skill 输出 JSON 是否 < 100KB？（现有测试验证）
- [ ] `retest` 命令是否能被 Skill 自然调用？

**发现的问题：**
1. SKILL.md 要求 `--use-llm` 但默认是 mock，用户需显式配置 API key —— 摩擦点
2. `skill-audit --suggest-only` 的 `TriggerPolicy` 只检查文件名关键字（auth、login 等），对文件内容不感知 —— 可能漏过
3. Installation Gate 依赖 `scripts/setup.ps1`，需要检查脚本是否存在且可用

#### B. CLI 方式

**评估项：**
- [ ] `vibe-sec audit --help` 是否完整？
- [ ] `vibe-sec retest --input` 流程是否清晰？
- [ ] 错误消息是否可操作？（如 "requires --api-key" 而非堆栈跟踪）
- [ ] `--verbose` 模式是否提供足够的调试信息？
- [ ] 报告文件路径是否合理？

**发现的问题：**
1. `audit` 命令不支持 `--changed-file`（只在 `skill-audit` 支持）—— 不一致
2. `retest` 命令的 `--input` 是 JSON 文件路径，但格式未在 --help 中说明
3. 默认使用 `MockLLMService`，行为与非 mock 模式差异大 —— 用户可能困惑

#### C. Python API 方式

**评估项：**
- [ ] `run_audit()` 函数签名是否清晰？
- [ ] `run_skill_audit()` vs `run_audit()` 区别是否明确？
- [ ] `OrchestrationConfig` 默认值是否合理？
- [ ] 异步 API 是否容易集成？

### 3.2 触发策略评估

当前 `TriggerPolicy` 逻辑：
```python
SENSITIVE_MARKERS = ("auth", "login", "permission", "upload", "download",
                      "prompt", "mcp", "tool", "secret", "token", "password",
                      "subprocess", "shell", "workflow", "innerhtml")

def evaluate(self, changed_paths, *, explicit=False):
    if explicit: return TriggerDecision(True, "explicit", ...)
    if matched:  return TriggerDecision(False, "suggest", ...)
    return TriggerDecision(False, "none", [])
```

**评估：**
- ✅ 保守策略（非 explicit 从不自动触发审计，只建议）
- ⚠️ 关键字列表有限：缺少 `eval`, `exec`, `os.system`, `popen`, `dangerouslySetInnerHTML` 等
- ⚠️ 只匹配文件名，不分析内容变更类型（新增/删除/修改的安全敏感代码行）
- ❌ 没有学习机制（不会从历史审计结果中调整触发策略）

### 3.3 整改闭环可用性

Skill Relay 状态机流程：
```
draft → dispatched → acknowledged → in_progress → completed → returned
```

**评估：**
- ✅ 状态机定义清晰
- ✅ `RemediationBundle` 包含 `ai_patch_prompt` 可直接供 coding agent 使用
- ✅ `retest` 验证 exploit 是否修复 + positive control 检查
- ⚠️ Skill Relay 依赖外部协作（coding agent 需主动更新状态），可能断裂

### 3.4 开发者体验评分表

| 体验维度 | 评分 (1-5) | 说明 |
|---------|-----------|------|
| 安装便捷性 | 3 | 需要 Docker + Python 3.11 + setup 脚本 |
| 首次使用体验 | 3 | doctor 检查友好，但 --use-llm 需要额外配置 |
| CLI 易用性 | 4 | 命令清晰，错误消息友好 |
| Skill 集成 | 4 | SKILL.md 定义完整，contract 稳定 |
| 报告可读性 | 4 | 多格式输出，Markdown 友好 |
| 整改可操作性 | 4 | ai_patch_prompt 可直接使用 |
| CI/CD 集成 | 2 | 缺少 GitHub Actions / GitLab CI 模板 |

---

## D4：建模部分的方法论评估

### 4.1 RuntimeSurface 模型分析

#### 4.1.1 提取正确性验证

**测试场景设计：**

| 场景 | 输入 | 预期提取 |
|------|------|---------|
| Python Flask 路由 | `@app.route('/login')` | PageEntry(/login, POST) |
| FastAPI 路由 | `@app.get("/items")` | PageEntry(/items, GET) |
| JS Express 路由 | `app.get('/api', handler)` | PageEntry(/api, GET) |
| Python prompt 变量 | `system_prompt = "You are..."` | PromptConfig(name=system_prompt) |
| OpenAI 调用 | `client.chat.completions.create(...)` | ModelInvocation(provider=openai) |
| MCP tool 装饰器 | `@mcp.tool()` | McpCapability + ToolProfile |
| innerHTML 赋值 | `el.innerHTML = userInput` | BrowserSink(sink_type=innerHTML) |
| localStorage | `localStorage.setItem('token', v)` | StorageAsset(type=local_storage) |
| GitHub Actions | `.github/workflows/ci.yml` | WorkflowNode × N |
| 硬编码密钥 | `API_KEY = "sk-xxx"` | 需由 AuditAgent 检测，非 Surface |

#### 4.1.2 边界条件测试

| 测试 | 预期行为 |
|------|---------|
| 空项目（无源文件） | RuntimeSurface 空但有有效 metadata |
| 超大文件（>1MB） | 跳过并记录到 skipped_large_files |
| 语法错误的 Python 文件 | 记录到 parse_failures，不崩溃 |
| 嵌套目录（含 node_modules） | 跳过 _IGNORED_DIRS |
| 混合语言项目 | 正确识别 Python + JS + YAML |
| Tree-sitter 不可用 | JS 提取降级，记录到 coverage.parse_failures |

#### 4.1.3 方法论审查

**RuntimeSurface 的 "复合运行时面" 模型：**

该模型定义了 12 种一级实体类型：

```
PageEntry          — HTTP/API 入口
PromptConfig       — 提示词/指令配置
ModelInvocation    — LLM 调用点
ToolProfile        — 工具定义
McpCapability      — MCP 能力注册
PermissionProfile  — 权限/认证声明
BrowserSink        — 浏览器端危险 sink
StorageAsset       — 存储操作（数据库/文件/Web Storage）
ExternalContentInput — 外部内容输入
WorkflowNode       — CI/CD 工作流节点
TrustBoundaryDefinition — 信任边界
CodeBlock          — 代码块（函数/类）
```

**正确性分析：**

✅ **优势：**
1. 覆盖面广 — 同时覆盖传统 Web 面和 AI Agent 面
2. 源证据锚定 — 每个实体都有 file_path + line_start/end
3. 去重机制 — 基于序列化 JSON 的去重
4. 多语言支持 — Python AST + Tree-sitter(JS/TS) + 框架语义(Java/Go)
5. 配置感知 — 从 package.json / Claude Desktop config 提取 MCP

⚠️ **局限：**
1. **Python AST 深度有限** — 无法处理动态路由构建 `app.route(f"/user/{id}")`
2. **JS 分析依赖 Tree-sitter** — 不可用时完全跳过
3. **框架语义仅有路由+权限** — Spring Security 的复杂授权链无法完整建模
4. **MCP 动态注册** — 仅标记 `dynamic_registration=True`，无法枚举运行时能力
5. **没有数据流分析** — 外部输入和 sink 是独立提取的，连接关系由 RiskChain 后续推断

### 4.2 RiskChain 模型分析

#### 4.2.1 风险链构造逻辑审查

```python
RiskChain:
  source_signal     → 攻击入口（用户输入/外部数据/配置）
  preconditions     → 前置条件（认证/授权/环境）
  boundary_path     → 边界穿越序列
  impact_hypothesis → 影响假设
  evidence_predicates → 证据谓词列表
```

**正确性测试：**

| Finding 类型 | 预期 source_signal | 预期 boundary_path |
|-------------|-------------------|-------------------|
| sql_injection | user_input, unvalidated | data_validation boundary, bypass_possible=True |
| hardcoded_password | configuration, credential | 从 TrustBoundary 匹配 |
| prompt_injection | external_data, unvalidated | authorization boundary (MCP) |
| xss | user_input, unvalidated | data_validation boundary |

**审查发现的问题：**

1. **默认边界构造过于宽松**：
   ```python
   if not boundary_path:
       boundary_path.append(BoundaryCrossing(
           from_zone="user_input", to_zone="application_logic",
           bypass_possible=True,  # 总是假设可绕过!
       ))
   ```
   当找不到匹配边界时，默认假设安全边界不存在且可绕过。这会导致 **RiskChain 总是显示高风险路径**，即使实际有安全控制。

2. **`_identify_source_signal` 用固定映射而非动态分析**：
   — 没有检查实际代码中是否有用户输入或外部数据来源
   — 纯基于 `vulnerability_type` 分类

3. **`calculate_confidence` 的权重因子是硬编码的**（0.6, 0.8, 1.2），没有校准依据

4. **没有考虑缓解因素**（如 WAF、CSP、输入长度限制）

#### 4.2.2 可用性评估

RiskChain 在报告中的呈现方式：
- Orchestrator 在 Merge 阶段通过 `RiskChainBuilder` 为每个 finding 附加 risk_chain
- 只有 `surface_object` 可用时才构建（需要 SurfaceAgent 成功运行）
- 如果 RiskChainBuilder 失败，只 log warning 不会中断流程

⚠️ **可用性问题：** RiskChain 失败时不阻塞审计结果，用户看到 finding 但没有 risk_chain 字段时不知道原因。

### 4.3 VRTM 模型分析

#### 4.3.1 VRTM 方法论评估

VRTM (Versioned Runtime Threat Model) 的设计：

```
声明层 (VRTM Declaration)       ← 项目方声明的资产、信任假设
    +
观察层 (Graph Observations)     ← 审计/验证产生的证据观察
    +
分析层 (RuntimeThreatModelAnalyzer) ← 威胁假设生成 + 技术映射
    ↓
版本化快照 (VRTM Snapshot)       ← 可 diff 的不可变版本
```

**评估：**
- ✅ 版本化设计支持 CI 中的 `--fail-on-review` 门控
- ✅ 威胁假设映射到 ATT&CK 技术 ID (`T-INDIRECT-PROMPT-INJECTION` 等)
- ✅ Evidence level 渐进升级：`static_observed → runtime_observed → verified`
- ✅ 图 diff 支持安全变更审查

⚠️ **局限：**
1. **声明层需要人工填写** — `model-init` 生成的模板全为空，依赖开发者自行填写
2. **威胁假设的 flow_planes 概念较新** — 未在行业标准中找到对应验证
3. **覆盖度不代表安全度** — 文档说明了这点，但容易被误读
4. **图指纹** 基于内容哈希，稍有不一致就视为不同（敏感但可能过于敏感）

#### 4.3.2 VRTM 边界测试

| 测试 | 预期 |
|------|------|
| 两次相同构建产生相同指纹 | ✅ `content_fingerprint()` 应相同 |
| 添加观察后指纹变化 | ✅ evidence level 升级应改变指纹 |
| evidence_level 不能降级 | ✅ `static_observed` 不会被 `runtime_observed` 覆盖 |
| 非法 observations 被拒绝 | ✅ 没有证据引用的 "verified" 级别被拒绝 |
| diff 正确识别变更节点 | ✅ changed_nodes 精确匹配 |
| 空项目产生最小模型 | ⚠️ 需验证不会崩溃 |

### 4.4 建模方法论的总体评级

| 方法 | 正确性 | 可用性 | 创新性 |
|------|--------|--------|--------|
| RuntimeSurface 提取 | 4/5 | 4/5 | 4/5 |
| RuntimeSurfaceGraph 边 | 3/5 | 3/5 | 4/5 |
| RiskChain 构造 | 3/5 | 3/5 | 4/5 |
| VRTM 威胁建模 | 3/5 | 2/5 | 5/5 |
| ThreatModelAnalyzer | 3/5 | 3/5 | 4/5 |

**关键改进建议：**
1. RiskChain 的默认边界假设需要从不安全改为 "unknown"
2. 添加缓解因素检测（CSP header、rate limiting、WAF）
3. VRTM 声明层需要更多引导（交互式填写或从配置自动提取）
4. Graph 边构造需要更多数据流证据（目前主要是静态引用匹配）

---

## 执行计划

### 第一轮：D1 基础（立即执行）
1. 运行现有测试套件
2. 对 fixtures 执行审计（基线）
3. 对平台自身执行自审计（dogfooding）
4. 运行 linting

### 第二轮：D1 深度（需额外准备）
5. 选择真实 OSS 项目进行审计
6. 手工验证发现的漏洞
7. 计算检测率/精确率

### 第三轮：D2 对比
8. 在相同 fixtures 上运行 bandit/semgrep
9. 对比报告质量和结果差异
10. 编写对比分析报告

### 第四轮：D3/D4 分析
11. 工作流嵌入的端到端模拟
12. 建模方法论边界条件测试

---

*文档版本：v1.0 | 日期：2026-07-27*
