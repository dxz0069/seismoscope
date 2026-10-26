# Vibe Sec Platform — 测试发现完整记录

> 测试周期：2026-07-27 ~ 2026-07-28
> 环境：Ubuntu 24.04 LTS / Python 3.12.3 / DeepSeek (deepseek-chat) / 4-core AMD EPYC
> 范围：单元测试 + LLM 增强审计 + 自审计 + 靶场审计 + VRTM 建模 + RuntimeSurface 图分析

---

## 目录

1. [概览](#概览)
2. [问题 1：RuntimeSurfaceGraph 84% 节点孤立](#问题-1runtimesurfacegraph-84-节点孤立)
3. [问题 2：excessive_agency 大规模误报](#问题-2excessive_agency-大规模误报)
4. [问题 3：验证瓶颈 — 97% 候选未审查](#问题-3验证瓶颈--97-候选未审查)
5. [问题 4：tree-sitter 在两处独立阻塞](#问题-4tree-sitter-在两处独立阻塞)
6. [问题 5：LLM 审查降级与验证率为零](#问题-5llm-审查降级与验证率为零)
7. [问题 6：RiskChain 默认假设边界可绕过](#问题-6riskchain-默认假设边界可绕过)
8. [问题 7：TriggerPolicy 仅做文件名匹配](#问题-7triggerpolicy-仅做文件名匹配)
9. [问题 8：Mock/LLM 模式行为差异](#问题-8mockllm-模式行为差异)
10. [问题 9：代码质量问题](#问题-9代码质量问题)
11. [测试数据附录](#测试数据附录)

---

## 概览

| # | 严重度 | 类别 | 问题 | 根因 |
|---|--------|------|------|------|
| 1 | 🔴 严重 | 建模 | RuntimeSurfaceGraph 84% 节点孤立 | 基于"同文件"启发式连接，无数据流分析 |
| 2 | 🔴 严重 | 精度 | excessive_agency 345 个候选几乎全误报 | 关键字匹配过于宽泛 |
| 3 | 🔴 严重 | 架构 | max_verification_count=20 导致 97% 候选未审查 | 默认值不适配真实项目规模 |
| 4 | 🟡 中等 | 基础设施 | tree-sitter 在 2 处独立阻塞 | Rust 原生下载无超时保护 |
| 5 | 🟡 中等 | 架构 | LLM 审查曾 74% 降级，验证率仍为 0 | FinalizeFinding/FinalizeVerification 合约过严 |
| 6 | 🟡 中等 | 方法论 | RiskChain 默认假设边界可绕过 | 找不到边界时虚构不安全路径 |
| 7 | 🟡 中等 | 功能 | TriggerPolicy 仅做文件名匹配 | 18 个关键字，无内容感知 |
| 8 | 🟢 低 | 流程 | Mock/LLM 模式行为差异 | 两套代码路径，verdict 语义不一致 |
| 9 | 🟢 低 | 代码 | 53 个 lint 问题 | unused-import, bare-raise 等 |

---

## 问题 1：RuntimeSurfaceGraph 84% 节点孤立

### 现象

对 finbot-ctf（499 文件）运行审计后，生成的 RuntimeSurfaceGraph 包含：
- **3026 个节点**
- **490 条边**
- **2536 个节点（84%）没有任何边连接**

### 节点来源分析

每个 RuntimeSurface 实体都被转化为一个图节点：

```
节点类型              数量    占比    来源
─────────────────────────────────────────────
code_block           2092    69%    每个 Python 函数/类都是独立节点
storage_asset         322    11%    每次 DB 查询、文件读写
trust_boundary        211     7%    每个入口 + 每个 MCP 都生成一个边界
entry_point           185     6%    每个 HTTP 路由
browser_sink          122     4%    每个 innerHTML / 危险 DOM 操作
tool                   28     1%    每个工具函数定义
mcp_capability         25     1%    每个 MCP Server/Tool/Resource 注册
privileged_asset       13     <1%   高风险工具/工作流自动生成
workflow               10     <1%   CI/CD YAML 中的 job 和 step
external_content        9     <1%   request.args/form/json 等外部输入
prompt                  4     <1%   system_prompt / instruction 变量
model                   4     <1%   LLM API 调用点
external_actor          1     <1%   始终创建的外部攻击者节点
─────────────────────────────────────────────
总计                 3026   100%
```

### 边的生成逻辑

边通过 `RuntimeSurfaceGraph.from_surface()` 方法（`core/harness/models.py:583-968`）生成。核心策略是**基于文件路径的启发式匹配**：

| 边关系 | 数量 | 连接策略 |
|--------|------|---------|
| actor → entry_point | 185 | 每个路由入口连接外部攻击者 |
| entry_point → code_block | 185 | 路由 → **同文件**的处理函数 |
| MCP → tool | 25 | MCP 注册 → **同名**工具 |
| MCP → trust_boundary | 25 | MCP 跨越授权边界 |
| entry_point → external_content | 24 | 路由接收的外部输入 |
| tool/MCP → privileged_asset | 13 | 高风险工具访问受保护资产 |
| tool/MCP → storage_asset | 11 | 工具读写**同文件**的存储操作 |
| actor → external_content | 9 | 外部攻击者控制内容 |
| workflow job → step | 9 | CI 任务执行步骤 |
| prompt → code_block | 4 | 提示词 → **同文件**代码 |

### 根因：连接策略的三个局限

**局限 1："同文件"假设**

入口和处理器必须在同一个文件才算连接：

```python
# core/harness/models.py:681-682
handler_id = code_by_name.get((entry.file_path, entry.handler_function or ""))
targets = [handler_id] if handler_id else in_file(code_by_file, entry.file_path)[:1]
#                                                                    ^^^^^^^^ 只取同文件
```

如果路由定义在 `routes.py` 而处理逻辑在 `handlers.py`，这条边就丢失了。

**局限 2："取第一个"截断**

`[:1]` 意味着一个路由只连接一个代码块。但实际代码中一个路由可能调用多个函数（验证 → 业务逻辑 → 数据库 → 返回）：

```python
# 只取同文件的第一个 code_block
targets = [handler_id] if handler_id else in_file(code_by_file, entry.file_path)[:1]
```

整个调用链被压缩成一个点。

**局限 3：没有数据流分析**

图没有追踪 `request.args['q']` → `query = f"...{q}..."`  → `cursor.execute(query)` 这样的 source-to-sink 路径。连接完全依赖文件位置巧合。

### 导致的后果

1. **84% 节点孤立** — 320/322 个 storage_asset、1903/2092 个 code_block、122/122 个 browser_sink 都没有边
2. **威胁假设路径受限** — 188 条 risk_path 只能在 16% 的连通子图上运行
3. **大量"巧合边"** — 同文件中的无关函数被错误关联
4. **缺少跨文件攻击链** — 真正的漏洞往往跨越多层（Controller → Service → DAO → DB），全部丢失

### 修复方向

1. **添加 AST 调用图分析**：追踪 Python 函数调用链 `a() → b() → os.system()`
2. **添加污点传播**：追踪 `request.args` 到 `execute()` 的 source-to-sink 路径
3. **去噪 code_block 节点**：只保留有安全相关性的函数（调用了危险函数 / 路由处理器 / 包含外部输入）
4. **跨文件连接**：通过 import 图和调用关系连接不同文件

### 涉及文件

- `core/harness/models.py:583-968` — `RuntimeSurfaceGraph.from_surface()` 图构造逻辑
- `core/surface/runtime_surface.py` — RuntimeSurface 实体提取
- `core/surface/threat_model.py` — 威胁假设生成

---

## 问题 2：excessive_agency 大规模误报

### 现象

finbot-ctf 审计发现 741 个候选漏洞，其中 **345 个（47%）** 被分类为 `excessive_agency`。典型误报示例：

```
[HIGH] excessive_agency: 智能体被赋予过高权限或缺乏人工监督
  File: tests/unit/agents/test_base_agent.py:25
  Evidence: autonomous

[HIGH] excessive_agency: 智能体被赋予过高权限或缺乏人工监督
  File: finbot/agents/base.py:76
  Evidence: permissions = "admin"
```

### 根因

AuditAgent 使用宽泛的正则模式匹配 `excessive_agency`：

```python
# agents/audit_agent.py 中的检测逻辑
# 匹配任何包含 "admin", "autonomous", "delete", "execute" 等关键字的赋值
"excessive_agency": r"(?i)(?:permissions?\s*[:=]\s*['\"]?(?:admin|\*)|auto(?:nomous)?[^\n]*(?:execute|approve))"
```

这导致以下情况全部被标记：
- 测试文件中的 mock 对象（`tests/unit/agents/`）
- 配置文件中的 `permissions = "admin"` 字面量
- 注释或文档字符串中的 "autonomous"
- 安全代码中的 `requires_approval = True`（这恰恰是安全控制而非漏洞）

finbot 是一个 **AI Agent 平台**，它的核心功能就是管理 Agent 权限。大量合法的 Agent 配置代码被误报为漏洞。

### 实际数据

| 标记位置 | 数量 | 是否为真漏洞 |
|----------|------|-------------|
| `tests/` 测试文件 | ~150 | ❌ 测试 fixture |
| `finbot/agents/` 核心代码 | ~120 | ⚠️ 需逐个审查 |
| `finbot/static/js/` 前端 | ~50 | ❌ 前端权限展示 |
| 其他 | ~25 | ⚠️ 不确定 |

### 修复方向

1. 排除测试目录（`tests/`、`*_test.py`、`test_*.py`）
2. 区分 "权限声明" 和 "权限缺失" — `requires_approval=True` 是安全控制
3. 将 excessive_agency 的检测从纯关键字匹配提升为语义分析：检查 Agent 是否真的在没有审批的情况下执行破坏性操作
4. 添加白名单模式（如 `@requires_approval` 装饰器）

---

## 问题 3：验证瓶颈 — 97% 候选未审查

### 现象

finbot-ctf 的 741 个候选中：

| 状态 | 数量 | 占比 |
|------|------|------|
| Verified | 1 | 0.1% |
| Needs evidence | 19 | 2.6% |
| **Not reviewed** | **721** | **97.3%** |

### 根因

`OrchestrationConfig` 的验证预算被硬限制：

```python
# core/orchestrator/orchestrator.py:88-89
verification_threshold: float = 0.6   # 只有置信度 >= 0.6 的才验证
max_verification_count: int = 20      # 最多验证 20 个！
```

而 `_filter_findings_for_verification()` 方法：

```python
# core/orchestrator/orchestrator.py:1182-1198
filtered = [f for f in all_findings if f.get("confidence", 0) >= verification_threshold]
filtered.sort(key=lambda f: severity_order.get(f.get("severity", "low"), 4))
selected = filtered[:self.orch_config.max_verification_count]  # 硬截断到20个！
```

### 问题

1. **20 个上限对真实项目严重不足**：fixture 项目只有 15 个候选所以刚好，但真实项目有 700+
2. **按严重度排序后截断**：只有 severity=critical 的 4 个 + severity=high 的前 16 个进入验证，其余全部丢弃
3. **Mock 模式下置信度统一为 0.6-0.7**：几乎所有候选都过阈值，但只能取 20 个
4. **没有分批验证或增量验证机制**

### 修复方向

1. 将 `max_verification_count` 改为动态计算（如 `max(20, total_candidates * 0.3)`）
2. 添加按漏洞类型分层抽样（每种类型至少验证 3 个）
3. 支持增量验证：第一轮验证 Top-N 后，可以继续验证下一批
4. 在报告中明确标注 "X candidates deferred due to verification budget"

---

## 问题 4：tree-sitter 在两处独立阻塞

### 现象

对 vibe-sec-platform 自身运行审计时，SurfaceAgent 卡住超时：

```
ValueError: Surface modeling failed: Download error:
Failed to download https://github.com/xberg-io/tree-sitter-language-pack/
releases/download/v1.13.3/parsers-linux-x86_64.tar.zst: timeout: global
```

### 根因

`tree-sitter-language-pack` 的 `get_parser()` 是 Rust 原生函数，在首次调用时需要从 GitHub 下载约 18MB 的解析器二进制文件。在中国服务器上访问 GitHub 超时，Rust 函数不返回，Python 层无法捕获异常。

**关键问题**：这种阻塞在两处独立出现，修复一处后另一处仍会卡住：

**阻塞点 1**：`core/surface/runtime_surface.py:629`

```python
# _extract_javascript() 方法
parser = self._parser_cache.get(language)
if parser is None:
    parser = get_parser(language)    # ← Rust 调用，不返回
    self._parser_cache[language] = parser
tree = parser.parse(source)
```

已有修复：`try/except` + `_tree_sitter_failed` 标志 + fallback 路径

**阻塞点 2**：`core/tool_fabric/framework_semantics.py:369`

```python
# _analyze_tree_sitter_lines() 方法
try:
    tree = get_parser(language).parse(content.encode("utf-8", errors="replace"))
    # ← 同上，Rust 调用不返回，except 永不到达
except Exception as exc:
    parser_failure = f"tree_sitter_runtime_unavailable:{type(exc).__name__}"
```

**这处没有 `_tree_sitter_failed` 标志，也没有 fallback 开关。**`framework_semantics.py` 有自己独立的 `get_parser` import，不受 `runtime_surface.py` 中的设置影响。

### 当前状态

测试时通过 sed 临时修补绕过：
- `runtime_surface.py:336` → `self._tree_sitter_failed = True`
- `framework_semantics.py:12` → `get_parser = None`

### 修复方向

1. 两处都使用 `ThreadPoolExecutor` + timeout 包装 `get_parser()` 调用
2. 或统一创建一个 `tree_sitter_loader` 工具模块，集中管理超时和 fallback
3. 或预置解析器到 Docker 镜像中，完全避免运行时下载

### 涉及文件

- `core/surface/runtime_surface.py:22-25, 336, 619-640`
- `core/tool_fabric/framework_semantics.py:12-14, 352-377`

---

## 问题 5：LLM 审查降级与验证率为零

### 5a. ReAct 审查降级（已在 2026-07-27 修复中解决 74%→26%）

**修复前**（`core/audit/react_review.py`）：

| 配置项 | 修复前 | 修复后 |
|--------|--------|--------|
| max_turns | 10 | 15 |
| force_terminal_after_turn | 6 | 12 |
| force_terminal_after_tool_results | 4 | 9 |
| FinalizeFinding evidence_bundle | required | optional |
| operational_gaps vs evidence_gaps | 未区分 | 已区分 |

**结果**：ReAct 完成率从 26% (8/31) 提升到 74% (20/27)。

### 5b. 验证率仍为零

即使审计阶段的 ReAct 改善，验证阶段仍无法产生 `verified` 结果：

**fixture 审计**（修复后）：LLM 0 verified，No-LLM 6 verified
**finbot 审计**（修复后）：LLM 待完成，No-LLM 1 verified / 721 not reviewed

原因：

1. **验证白名单不覆盖 LLM 发现的新类型**：`code_injection`、`context_manipulation`、`mcp_tool_poisoning` 等不在 `VerificationAgent.SUPPORTED_TYPES` 中
2. **动态验证依赖 PoC 计划**：LLM 审计不生成 `poc_plan`，导致 `VerificationAgent._dynamic_verification()` 直接返回 unavailable
3. **FinalizeVerification 合约同样过严**：验证阶段的 ReAct 有独立的问题（与审计阶段类似）

---

## 问题 6：RiskChain 默认假设边界可绕过

### 根因

```python
# core/surface/risk_chain.py:395-404
def _build_boundary_path(self, finding):
    boundary_path = []
    for boundary in self.runtime_surface.trust_boundaries:
        if boundary.file_path == finding.get("file_path"):
            boundary_path.append(...)

    if not boundary_path:
        # 问题：找不到边界时，虚构了一条无验证、可绕过的路径
        boundary_path.append(BoundaryCrossing(
            from_zone="user_input",
            to_zone="application_logic",
            boundary_type="data_validation",
            validation_mechanism=None,      # 没有验证机制
            bypass_possible=True,           # 默认可绕过！
        ))
```

### 影响

1. `calculate_confidence()` 中的 `boundary_factor` 总是 1.2（可绕过），系统性推高风险评分
2. 安全审计平台不应该默认假设不安全

### 状态

已在 `docs/progress/ISSUES_FOUND.md` 记录的修复中解决：找不到边界时标记 `boundary_gap: true` 而非虚构路径。

---

## 问题 7：TriggerPolicy 仅做文件名匹配

### 根因

```python
# core/policy/trigger_policy.py:23-36
SENSITIVE_MARKERS = (
    "auth", "login", "permission", "upload", "download",
    "prompt", "mcp", "tool", "secret", "token", "password",
    "subprocess", "shell", "workflow", "innerhtml",
)

def evaluate(self, changed_paths, *, explicit=False):
    matched = [path for path in paths
               if any(marker in path.lower() for marker in self.SENSITIVE_MARKERS)]
```

### 缺陷

1. 只检查文件名，不分析 diff 内容（修改注释也触发）
2. 不区分文件类型（`README.md` 中的 password 也触发）
3. 缺少危险标记：`eval`, `exec`, `dangerouslySetInnerHTML`, `bypass`
4. 无权重/优先级 — 所有标记一视同仁

### 状态

已在 `docs/progress/ISSUES_FOUND.md` 记录的修复中解决：支持 diff 内容分析、代码文件过滤、风险权重和 `.vibe-sec/trigger-policy.yaml` 自定义。

---

## 问题 8：Mock/LLM 模式行为差异

### 现象

对相同的 fixtures 项目，No-LLM 模式验证了 6 个漏洞，LLM 模式验证了 0 个。

### 根因

两套代码路径的 verdict 语义不一致：

**No-LLM 路径**：
```
AuditAgent → 静态匹配 → candidate → 跳过 ReAct → 验证 →
hardcoded_password ∈ STATIC_CONFIRMABLE → verified ✓
```

**LLM 路径**：
```
AuditAgent → ReActDiscovery → ReActReview → FinalizeFinding →
degraded? → verdict=potential →
验证 → potential ≠ confirmed → needs_evidence ✗
```

关键瓶颈：LLM 审查的 `verdict=potential` 无法触发 `can_confirm_statically` 路径，即使两种模式下的实际证据完全相同。

### 状态

No-LLM 验证数已从 3 增加到 6（通过扩展 `SUPPORTED_TYPES` 和验证别名），但 LLM 路径的 verdict 桥接问题待解决。

---

## 问题 9：代码质量问题

### ruff 扫描结果

```
ruff check . --select F,B
Found 53 errors.
```

| 类型 | 数量 | 示例位置 |
|------|------|---------|
| F401 unused-import | 31 | `agents/audit_agent.py:28` TaskHandoff |
| B007 unused-loop-variable | 5 | 循环变量未使用 |
| B904 bare-raise | 5 | except 中直接 raise 而非 `raise ... from err` |
| F841 unused-variable | 5 | 赋值后未使用 |
| B905 zip-without-strict | 4 | zip() 缺少 strict=True |
| F541 f-string-missing-placeholders | 2 | f-string 无占位符 |
| B027 empty-method | 1 | 空方法缺少 @abstractmethod |

### 状态

已在 `docs/progress/ISSUES_FOUND.md` 记录的修复中全部解决。

---

## 测试数据附录

### A. 单元测试

```
154 passed, 3 failed, 7 skipped in 475.71s
```
3 个失败均为 tree-sitter GitHub 下载超时。

### B. Fixture 审计 — No-LLM vs LLM 对比

| 指标 | No-LLM (修复前) | LLM (修复前) | No-LLM (修复后) | LLM (修复后) |
|------|----------------|-------------|----------------|-------------|
| 候选漏洞 | 15 | 29 | 15 | 24 |
| Verified | 3 | 0 | **6** | 0 |
| Rejected | 2 | 0 | 0 | 1 |
| Needs Evidence | 10 | 20 | 7 | 19 |
| Not Reviewed | 0 | 9 | 2 | 4 |
| 漏洞类型数 | 5 | 14 | 5 | ~12 |
| ReAct 完成率 | N/A | 26% (8/31) | N/A | **74%** (20/27) |
| ReAct 降级率 | N/A | 74% (23/31) | N/A | **26%** (7/27) |

### C. finbot-ctf 审计

| 指标 | 值 |
|------|-----|
| 文件数 | 499 (327 代码文件) |
| 候选漏洞 | 741 |
| Verified | 1 (SQL 注入) |
| Not Reviewed | 721 (97%) |
| 图节点 | 3026 |
| 图边 | 490 |
| 孤立节点 | 2536 (84%) |
| 风险路径 | 188 |
| 可视化视图 | data / instruction / authority / artifact |

### D. LLM 独有发现的漏洞类型（对比 Mock 模式）

`code_injection`, `mcp_tool_poisoning`, `xss`, `path_traversal`,
`hardcoded_secrets`, `missing_authentication`, `context_manipulation`,
`hardcoded_credentials`, `denial_of_service`

### E. 服务器端测试结果文件

```
/root/vibe-sec-platform/test-results-v2/
├── d2-fixture-no-llm.json    (4.8MB)
├── d3-fixture-llm.json       (280MB, 含 ReAct 全轨迹)
├── b3-finbot.json            (59MB, RuntimeSurface + 741 findings)
└── b4-finbot-llm.json        (运行中)
```

---

*文档版本：v2.0 | 日期：2026-07-28 | 基于服务器端全量测试*
