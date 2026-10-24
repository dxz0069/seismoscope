# Vibe Sec Platform — 测试发现问题记录

> 测试日期：2026-07-27 | 测试环境：Ubuntu 24.04 LTS, Python 3.12.3, DeepSeek (deepseek-chat)
> 测试范围：单元测试 + LLM 增强审计 + 自审计 + VRTM 建模 + 横向对比

---

## 总览

| # | 严重度 | 问题 | 根因类型 | 修复难度 |
|---|--------|------|---------|---------|
| 1 | 🔴 HIGH | 74% LLM 审查降级 — FinalizeFinding 难以满足 | 架构参数 | 中 |
| 2 | 🔴 HIGH | LLM 审计验证率 0% — 验证白名单覆盖不足 | 设计不对称 | 中 |
| 3 | 🟡 MEDIUM | tree-sitter 依赖 GitHub 下载 — 自审计被阻断 | 基础设施 | 低 |
| 4 | 🟡 MEDIUM | TriggerPolicy 仅做文件名匹配 | 功能不完整 | 低 |
| 5 | 🟡 MEDIUM | RiskChain 默认假设所有边界可绕过 | 方法论缺陷 | 低 |
| 6 | 🟢 LOW | Mock/LLM 模式行为差异导致验证结果矛盾 | 流程设计 | 中 |
| 7 | 🟢 LOW | 代码质量问题：53 个 lint 问题 | 代码规范 | 低 |

---

## 问题 1：74% LLM 审查降级

**严重度**：🔴 HIGH
**涉及文件**：`core/audit/react_review.py:260-371`、`core/agent_runtime/loop.py:146-382`

### 现象

对 fixtures 目录运行 LLM 增强审计时，31 个 ReAct 审查任务中只有 8 个 (26%) 完成了有效审查，23 个 (74%) 被标记为 `degraded`（降级）。

### 根因

有三层原因叠加导致此问题。

#### 第一层：Turn 预算不足

审查采用 ReAct 循环（观察 → 工具调用 → 证据收集 → FinalizeFinding）。`AgentTaskLoop` 设置了硬性 turn 限制：

```python
# core/agent_runtime/loop.py:253
if task.turn_count >= self.max_turns:
    return await self._fail(task, machine, "maximum turn limit reached")
```

`ReActFindingReviewer` 的 `max_turns` 默认为 10，但同时 `ReActConfig` 强制限制：

```python
# core/audit/react_review.py:324-325
force_terminal_after_turn=6,          # 第 6 轮后强制调用 FinalizeFinding
force_terminal_after_tool_results=4,  # 4 个工具结果后强制
```

LLM 实际只有 6 个推理回合来完成：阅读代码 → 调用 read_source → 调用 trace_python_flow → 检查 surface → 确认证据 → 调用 FinalizeFinding。对于需要跨文件追踪数据流（如 SQL 注入从 request 到 execute）的漏洞，6 轮远远不够。

#### 第二层：FinalizeFinding 合约过于严格

FinalizeFinding 要求 LLM 在一次 tool call 中输出 13 个必填字段的复杂嵌套 JSON：

```python
# core/audit/react_review.py:186-192
"required": [
    "id", "title", "severity", "vulnerability_type", "description",
    "file_path", "line_start", "line_end", "verdict", "evidence_bundle",
]
```

`evidence_bundle` 内部还包含 `items` 数组和 `gaps` 数组。对于 DeepSeek 模型，在一次调用中生成如此复杂的嵌套结构，经常出现：字段遗漏、JSON 格式错误、verdict 值不在枚举范围内。

#### 第三层：降级逻辑过于激进

即使 LLM 完成了所有步骤，`_bind_review_result` 函数还会进行二次降级：

```python
# core/audit/react_review.py:437-450
# 没有成功 source_read 的 confirmed 降为 potential
if verdict in {"confirmed", "verified"} and (gaps or not source_records):
    verdict = "potential"

# 路径依赖类型必须有跨文件语义追踪
if (verdict in {"confirmed", "verified"}
    and vuln_type in PATH_DEPENDENT_TYPES
    and not semantic_records):
    verdict = "potential"
```

最关键的是，一旦运行状态不是 `"completed"`，置信度被强制压到 0.69 以下：

```python
# core/audit/react_review.py:470
if degraded:
    confidence = min(confidence, 0.69)
```

这导致编排器的 `verification_threshold=0.6` 虽然能通过，但 `VerificationAgent._select_verification_method` 对 medium 及以下只做 basic 验证。

### 影响

- LLM 分析质量无法在最终结果中体现
- 跨文件数据流追踪类漏洞几乎不可能被 confirm
- 用户看到大量 `needs_evidence`，但无法区分"真的缺证据"还是"审查被截断"

### 修复建议

1. 将 `force_terminal_after_turn` 从 6 增加到 12-15，赋予 LLM 更多探索空间
2. 简化 `FinalizeFinding` 合约，将 `evidence_bundle` 改为可选字段
3. 对于 `degraded` 的结果，区分"超时截断"和"证据不足"两种情况
4. 考虑分阶段审查：第一轮做浅层确认（confirmed/potential），第二轮做深度追踪

---

## 问题 2：LLM 审计验证率 0%

**严重度**：🔴 HIGH
**涉及文件**：`agents/verification_agent.py:61-68, 296-390`

### 现象

LLM 发现的 29 个漏洞中，0 个被验证（verified），20 个标记为 `needs_evidence`，9 个未审查。相比之下，No-LLM 模式验证了 3 个（全部是 hardcoded_password 类型）。

### 根因

#### 第一层：LLM 发现的漏洞类型不在验证白名单中

VerificationAgent 维护了两个关键白名单：

```python
# agents/verification_agent.py:62-68
SUPPORTED_TYPES = {
    "sql_injection", "command_injection", "xss", "path_traversal",
    "hardcoded_password", "api_key", "secret_leak", "credential_exposure",
    "dependency_vulnerability", "prompt_injection", "mcp_insecurity",
    "excessive_agency", "ssrf", "unsafe_deserialization", "workflow_insecurity",
    "authorization_bypass", "broken_access_control",
}

# 只有这 5 种可以仅靠静态分析确认
STATIC_CONFIRMABLE = {
    "hardcoded_password", "api_key", "secret_leak", "credential_exposure",
    "dependency_vulnerability",
}
```

LLM 发现了 9 种不在 `SUPPORTED_TYPES` 中的新类型：

| LLM 发现的类型 | 在 SUPPORTED_TYPES 中？ |
|---------------|----------------------|
| `code_injection` | ❌ |
| `mcp_tool_poisoning` | ❌ |
| `hardcoded_secrets` | ❌ |
| `hardcoded_credentials` | ❌ |
| `missing_authentication` | ❌ |
| `context_manipulation` | ❌ |
| `denial_of_service` | ❌ |

当验证 Agent 遇到这些类型时，`_static_verification` 直接返回 unsupported：

```python
# agents/verification_agent.py:302-311
if vuln_type not in self.SUPPORTED_TYPES:
    return VerificationEvidence(
        "static",
        f"No Harness-owned verification predicate is registered for {vuln_type}",
        False,
        ...
        outcome="unsupported",
    )
```

#### 第二层：动态验证依赖不存在的 PoC 计划

对于在支持列表中的类型，验证流程是：

```
静态分析 → can_confirm_statically? → verified
         → 否则 → 动态验证(Docker) → 无PoC计划 → needs_evidence
```

LLM 审计过程不生成 PoC 计划（`poc_plan` 字段为空），动态验证直接返回 unavailable：

```python
# agents/verification_agent.py:503-507
if not validation.executable or validation.plan is None:
    return VerificationEvidence(
        "dynamic", "PoC plan is absent, invalid, or not authorized", False,
        ..., outcome="unavailable",
    )
```

### 影响

- LLM 发现能力提升了 180%（14 种 vs 5 种类型），但验证能力未同步扩展
- 发现越多 → 未验证的漏洞越多 → 用户体验反而更差
- 形成"发现-阻塞-无法验证"的死循环

### 修复建议

1. 将 `STATIC_CONFIRMABLE` 扩展到所有有静态风险指示器的类型（至少包括 `command_injection`、`sql_injection`、`xss`）
2. 允许 LLM 在审计阶段生成 PoC 计划草案
3. 添加无需 Docker 的轻量级验证方法（如 AST 污点分析）
4. 当验证基础设施不可用时，使用 LLM 证据质量评估作为代理

---

## 问题 3：tree-sitter 依赖 GitHub 下载

**严重度**：🟡 MEDIUM
**涉及文件**：`core/surface/runtime_surface.py:612-615, 22-25`

### 现象

对 vibe-sec-platform 自身运行审计时，SurfaceAgent 在解析 JS/TS 文件时崩溃：

```
ValueError: Surface modeling failed: Download error: Failed to download
https://github.com/xberg-io/tree-sitter-language-pack/releases/download/
v1.13.3/parsers-linux-x86_64.tar.zst: timeout: global
```

### 根因

执行链路如下：

1. `RuntimeSurfaceBuilder.build()` 遍历所有源文件
2. 发现 `.js`/`.ts`/`.tsx` 文件时调用 `_extract_javascript()`
3. 该方法调用 `get_parser("javascript")` 获取 tree-sitter 解析器
4. `tree_sitter_language_pack` 内部 Rust 代码检测到本地没有解析器，从 GitHub 下载约 18MB 的 `parsers-linux-x86_64.tar.zst`
5. 中国服务器访问 GitHub 超时 → `DownloadError`

关键代码：

```python
# core/surface/runtime_surface.py:614-615
language = "tsx" if suffix in {".tsx", ".jsx"} else ...
tree = get_parser(language).parse(source)  # 触发下载，无超时控制
```

import 保护只覆盖了包安装失败的情况，不覆盖下载失败：

```python
# core/surface/runtime_surface.py:22-25
try:
    from tree_sitter_language_pack import get_parser
except ImportError:
    get_parser = None    # 不捕获下载超时
```

### 影响

- 平台无法对自身（及任何包含 JS/TS 文件的项目）进行完整审计
- 单元测试中 3 个相关测试因此失败
- 在网络受限环境中（如中国服务器），这是必现问题

### 修复建议

1. 在 Docker 镜像中预置 tree-sitter 解析器
2. 为 `get_parser()` 添加 timeout 和 try/except 保护
3. 添加降级模式：tree-sitter 不可用时仅使用 AST 分析，并报告 coverage gap
4. 支持通过环境变量或配置文件指定本地解析器路径

---

## 问题 4：TriggerPolicy 仅做文件名匹配

**严重度**：🟡 MEDIUM
**涉及文件**：`core/policy/trigger_policy.py:23-36`

### 现象

触发策略只能通过 18 个预定义关键字匹配文件路径名，完全不分析变更内容。

### 根因

```python
# core/policy/trigger_policy.py:23-36
class TriggerPolicy:
    SENSITIVE_MARKERS = (
        "auth", "login", "permission", "upload", "download",
        "prompt", "mcp", "tool", "secret", "token", "password",
        "subprocess", "shell", "workflow", "innerhtml",
    )

    def evaluate(self, changed_paths, *, explicit=False):
        paths = list(changed_paths)
        matched = [path for path in paths
                   if any(marker in path.lower()
                          for marker in self.SENSITIVE_MARKERS)]
        if explicit:
            return TriggerDecision(True, "explicit", ...)
        if matched:
            return TriggerDecision(False, "suggest", ...)
        return TriggerDecision(False, "none", [])
```

### 具体缺陷

1. **只检查文件名，不检查变更内容** — 修改 `auth.py` 中的注释也会触发审计建议
2. **不区分文件扩展名** — `README.md` 中的 "password" 一词也会触发
3. **缺少常见的危险标记** — 如 `eval`, `exec`, `os.system`, `dangerouslySetInnerHTML`, `raw` (Django), `bypass`, `unsafe`
4. **无权重机制** — 所有标记一视同仁，`auth.py` 和 `innerhtml_utils.ts` 同等对待
5. **无上下文感知** — 不检查是否真的是安全敏感变更（如新增路由 vs 修改日志格式）
6. **无学习机制** — 不会根据历史审计结果调整触发策略

### 影响

- 修改 `src/utils/password_validator.py`（添加安全的密码校验）→ 触发 suggest
- 修改 `src/config.py`（硬编码数据库密码）→ 也仅仅是 suggest
- 用户可能因过多的 low-value suggest 而忽略真正的风险

### 修复建议

1. 添加基于代码 diff 内容的变更感知（新增/删除了危险函数调用？）
2. 区分文件类型，只对代码文件进行敏感匹配
3. 添加标记权重和优先级
4. 支持 `.vibe-sec/trigger-policy.yaml` 自定义规则

---

## 问题 5：RiskChain 默认假设所有边界可绕过

**严重度**：🟡 MEDIUM
**涉及文件**：`core/surface/risk_chain.py:395-404`

### 现象

当 RuntimeSurface 中没有与 finding 匹配的 trust boundary 时，风险链默认创建一条不安全路径。

### 根因

```python
# core/surface/risk_chain.py:395-404
def _build_boundary_path(self, finding):
    boundary_path = []
    for boundary in self.runtime_surface.trust_boundaries:
        if boundary.file_path == finding.get("file_path"):
            boundary_path.append(BoundaryCrossing(
                ...
                bypass_possible=not boundary.validation_mechanism,
            ))

    # 问题在这里 ↓
    if not boundary_path:
        boundary_path.append(BoundaryCrossing(
            from_zone="user_input",
            to_zone="application_logic",
            boundary_type="data_validation",
            validation_mechanism=None,      # 无验证机制
            bypass_possible=True,           # 默认总是可绕过！
        ))
```

### 问题分析

1. 当 RuntimeSurface 中没有匹配的信任边界时（SurfaceAgent 失败、项目结构不常见、或是一个新的攻击面），系统不是报告 "unknown"，而是**主动创建了一条不安全的边界穿越**
2. RiskChain 的 `calculate_confidence()` 利用 `boundary_factor` 调整置信度：
   ```python
   # core/surface/risk_chain.py:191-196
   if bypassable_boundaries:
       boundary_factor = 1.2    # 可绕过 → 增加风险
   else:
       boundary_factor = 0.7    # 不可绕过 → 降低风险
   ```
   默认 `bypass_possible=True` 导致 boundary_factor 总是 1.2，系统性地推高风险评分
3. 安全审计平台的默认立场应该是"不确定"而非"不安全"。这是方法论层面的错误

### 影响

- 所有无法匹配到信任边界的 finding 都会得到偏高的风险评分
- 用户无法区分"真的是高风险路径"和"信息不足无法判断"
- 与"证据驱动的安全审查"这一核心设计原则矛盾

### 修复建议

1. 将默认 `bypass_possible` 改为 `False`，并添加 `boundary_status: "unknown"` 字段
2. 当找不到匹配边界时，标记 `boundary_gap: true` 而非创建虚构边界
3. 在报告中区分："有证据的边界"、"推断的边界"、"缺失的边界"

---

## 问题 6：Mock/LLM 模式行为差异

**严重度**：🟢 LOW
**涉及文件**：`agents/audit_agent.py`、`core/audit/react_review.py`

### 现象

No-LLM 模式验证了 3 个漏洞，LLM 模式验证了 0 个。两种模式在相同 fixtures 上产生完全不同的验证结果。

### 根因

两种模式的代码路径完全不同：

**No-LLM 路径 (MockLLMService)**：
```
AuditAgent._scan_* → 静态模式匹配 → candidate → 跳过ReAct → 直接进入verify
→ _static_verification → hardcoded_password ∈ STATIC_CONFIRMABLE → verified ✓
```

**LLM 路径 (DeepSeekService)**：
```
AuditAgent._scan_* → ReActDiscovery → 更多candidate → ReActReview →
FinalizeFinding → degraded? → verdict=potential →
_static_verification → potential ≠ confirmed → 无法confirmed → needs_evidence ✗
```

关键在于 `_bind_review_result` 的降级逻辑：当 LLM 审查为 degraded 时，verdict 被强制改为 `potential`。而 VerificationAgent 的静态验证对 `potential` 最多只能标记为 `needs_evidence`。只有 `confirmed` 且 `can_confirm_statically=True` 才能推进到 `verified`。

### 影响

- LLM 模式虽然发现了更多漏洞，但验证结果更差
- 用户可能得出结论"LLM 模式不如 Mock 模式"，而这恰恰相反
- Mock 模式有 3 个 verified 可能给用户虚假的安全感（Mock 的分析更浅，确认门槛更低）

### 修复建议

1. 统一两种模式的 verdict 语义 — `potential` 在 LLM 模式下应等同于 Mock 模式下的 "confirmed-by-static-analysis"
2. 在 No-LLM 模式下也标注 coverage gap（如"未经过 LLM 审查"）
3. 添加 verdict 一致性检查，当两种模式产生矛盾结果时发出警告

---

## 问题 7：代码质量问题

**严重度**：🟢 LOW
**涉及文件**：多个

### 现象

`ruff check . --select F,B` 扫描发现 53 个问题。

### 分类详情

| 类型 | 数量 | 严重度 | 说明 |
|------|------|--------|------|
| F401 unused-import | 31 | LOW | 如 `agents/audit_agent.py:28` 导入了 `TaskHandoff` 但未使用 |
| B007 unused-loop-variable | 5 | LOW | 循环变量未使用，建议改为 `_` |
| B904 bare-raise | 5 | MEDIUM | except 块中直接 raise，应使用 `raise ... from err` |
| F841 unused-variable | 5 | LOW | 赋值后未使用的变量 |
| B905 zip-without-strict | 4 | LOW | `zip()` 建议添加 `strict=True` |
| F541 f-string-missing-placeholders | 2 | LOW | f-string 中没有占位符 |
| B027 empty-method | 1 | LOW | 空方法缺少 `@abstractmethod` 装饰器 |

### 重点：B904 异常链丢失

```python
# 当前代码
except ValueError:
    valid = sorted(item.value for item in cls)
    raise ValueError(f"Invalid CandidateStatus {value!r}...")

# 应改为
except ValueError as err:
    valid = sorted(item.value for item in cls)
    raise ValueError(f"Invalid CandidateStatus {value!r}...") from err
```

当在 except 块中 raise 新异常而不使用 `from err`，原始异常的堆栈信息被丢弃。在生产环境中这会导致调试困难。

### 修复建议

1. 运行 `ruff check --fix` 自动修复 33 个问题
2. 手动修复 B904（5 处）和 B027（1 处）
3. 将 ruff 集成到 CI pipeline 中

---

## 测试数据参考

### 单元测试结果

```
154 passed, 3 failed, 7 skipped in 475.71s
```

3 个失败全部与 tree-sitter GitHub 下载超时相关。

### Fixture 审计对比

| 指标 | No-LLM | LLM (DeepSeek) |
|------|--------|---------------|
| 候选漏洞 | 15 | 29 |
| Verified | 3 | 0 |
| Rejected | 2 | 0 |
| Needs Evidence | 10 | 20 |
| Not Reviewed | 0 | 9 |
| 漏洞类型数 | 5 | 14 |
| ReAct Completed | N/A | 8 (26%) |
| ReAct Degraded | N/A | 23 (74%) |
| 审计通道 | web/agent/secrets | web/mcp/agent/secrets |

### LLM 独有发现的 9 种漏洞类型

`code_injection`, `mcp_tool_poisoning`, `xss`, `path_traversal`, `hardcoded_secrets`, `missing_authentication`, `context_manipulation`, `hardcoded_credentials`, `denial_of_service`

---

*文档版本：v1.0 | 生成日期：2026-07-27 | 基于服务器端全量测试*
