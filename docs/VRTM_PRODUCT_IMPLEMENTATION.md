# VRTM 产品实现说明

> 版本：0.2  
> 日期：2026-07-22  
> 目标：可独立部署、可持续演化、可供 Skill/CLI/API 调用的运行面威胁建模模块

## 1. 模块边界

VRTM 负责把源码、结构化配置、项目声明和智能体证据统一为四平面运行图，并输出可验证风险假设和版本变化。它不替代 Audit Agent 的源码调查，也不把风险假设直接声明为漏洞。

```text
RuntimeSurfaceBuilder
  + Project Declaration
  + Evidence-bound Graph Observations
  -> RuntimeSurfaceGraph
  -> RuntimeThreatModelAnalyzer
  -> Visualization / Coverage / Unknowns
  -> Graph Diff / Threat Diff / Security Change Analysis
  -> Immutable Local Snapshot
```

## 2. 代码结构

| 模块 | 职责 |
| --- | --- |
| `core/harness/vrtm.py` | 四平面、证据等级、关系语义、控制摘要和 Coverage |
| `core/harness/models.py` | 图、稳定 ID、Observation、指纹、diff 和前端投影 |
| `core/surface/threat_model.py` | Technique Catalog 和确定性风险假设 |
| `core/vrtm/declaration.py` | 严格 YAML 声明解析、校验和合并 |
| `core/vrtm/observations.py` | Audit/Verification Finding 到 Observation 的证据绑定 |
| `core/vrtm/lifecycle.py` | 风险状态、风险 diff 和安全显著变化分析 |
| `core/vrtm/store.py` | 原子写入、内容寻址的不可变快照 |
| `core/vrtm/service.py` | 独立产品服务入口和质量诊断 |
| `core/vrtm/exporters.py` | JSON、Markdown 和 Graphviz DOT 导出 |

## 3. 产品入口

### 3.1 CLI

```powershell
vibe-sec model-init <project-path>
vibe-sec model <project-path> --format json
vibe-sec model <project-path> --baseline <snapshot-id>
vibe-sec model <project-path> --observation evidence.json
vibe-sec model <project-path> --list-snapshots
vibe-sec model <project-path> --fail-on-review
```

`model` 不依赖 LLM、Docker 或外部扫描器。`--fail-on-review` 在检测到权限扩大、新边界穿越、新特权资产或控制退化时返回退出码 `2`。

### 3.2 Skill

`skill-audit` 在审计结束后保存证据增强模型。Audit 和 Verification 阶段分别输出 `vibe-sec.vrtm.evolution.v1`，最终结果包含：

- `runtime_graph_observations`；
- `vrtm_evolution`；
- `vrtm_snapshot`；
- 更新后的 `runtime_surface_graph`；
- 更新后的 `threat_model`。

`retest` 在整改应用后重新建模，与最新快照比较风险消除和安全变化。

### 3.3 API

- `POST /api/vrtm/models`；
- `GET /api/vrtm/models/latest`；
- `GET /api/vrtm/models`。

API 只接受已注册 `project_id`，声明路径不能逃逸项目根目录。服务默认监听 `127.0.0.1`，默认 CORS 仅包含本地开发源。远程部署必须在外层增加认证和访问控制。

## 4. 声明文件

默认位置为 `.vibe-sec/vrtm.yaml`：

```yaml
schema: vibe-sec.vrtm.declaration.v1
scope:
  environment: production
nodes:
  - key: runtime-agent
    type: runtime_agent
    label: Release Agent
    privilege_level: high
    attributes:
      capabilities: [release]
  - key: production
    type: deployment_asset
    label: Production Cluster
    attributes:
      access_control: workload-identity
edges:
  - source: runtime-agent
    target: production
    relation: deploys
assumptions:
  - Deployment identity policy is supplied by the platform team.
exclusions: []
```

解析器拒绝重复 YAML key、未知节点类型、未知关系、非法平面、重复节点 key、越界 confidence 和无效对象结构。无法解析的边引用进入错误诊断，使模型状态成为 `invalid`，且不写入版本库。

## 5. Observation 安全规则

Observation 只能指向现有稳定节点或边，不能由 LLM 任意创建拓扑。

| Evidence Level | 最低要求 |
| --- | --- |
| `inferred` | Agent、目标 ID 和推断记录 |
| `declared` | 项目声明来源 |
| `static_observed` | Tool 和 Evidence Reference |
| `runtime_observed` | 运行工具和 Evidence Reference |
| `verified` | Verification Agent、Tool、Evidence Reference 和 Verification Predicate |

较低等级 Observation 可以保留为审计历史，但不能覆盖更高等级事实。重复 Observation ID 被拒绝。事实更新使用节点类型白名单，避免通用 Agent 改写无关安全属性。

## 6. 证据连续性

模型在应用 Observation 前计算 `base_fingerprint`：

- 基础图未变化：沿用上一版本的 Observation 和风险状态；
- 基础图变化：旧 Observation 失效，不自动继承，并输出 `stale_observations_invalidated`；
- 新证据必须重新绑定到当前稳定 ID；
- Graph Fingerprint 包含最终证据状态，用于快照寻址。

该规则防止修改代码后继续沿用已过期的“verified”结论。

## 7. 风险生命周期

风险假设状态包括：

- `open`：尚未完成证据谓词；
- `supported`：至少一条绑定证据支持路径；
- `refuted`：绑定验证反驳且不存在支持证据；
- `mitigated`：整改和复测明确关闭。

多条 Observation 冲突时，已支持证据优先于单条反驳；只有整改复测能够进入 `mitigated`。模型版本差异另外输出新增、消除、变化和状态变化，避免把“当前不存在”与“已经验证修复”混为一谈。

## 8. Technique 覆盖

当前 Catalog 包含 14 类复合 Technique：

- Prompt Injection；
- Indirect Prompt Injection；
- Excessive Agency；
- MCP Description Injection；
- MCP Authorization Gap；
- Unprotected Entry；
- Browser Sink Injection；
- Workflow Privilege；
- Sensitive Storage Access；
- Memory Poisoning；
- Retrieval Injection；
- Secret Delegation；
- Deployment Tampering；
- Service Identity Overprivilege。

每类 Technique 包含四平面、路径模式、控制期望、验证策略，以及 STRIDE、MITRE ATT&CK/ATLAS、CWE/CAPEC、OWASP 的解释映射。

## 9. 质量与降级

`quality.status`：

- `complete`：图完整且没有当前诊断；
- `degraded`：图可用，但存在 Unknown、解析失败、旧证据失效或其他覆盖缺口；
- `invalid`：重复 ID、悬空边或声明完整性错误，禁止持久化。

质量报告分别展示图完整性、抽取 Coverage、证据 Coverage、Unknown 和诊断。不存在单一“安全分数”，`complete` 也不代表项目安全。

## 10. 持久化与导出

```text
.vibe-sec/vrtm/latest.json
.vibe-sec/vrtm/snapshots/<fingerprint-prefix>.json
```

快照使用随机临时文件和 `os.replace` 原子写入，相同内容指纹不重复创建。损坏的 `latest.json` 不阻止重新建模，但会产生 `invalid_previous_snapshot` 诊断。

导出格式：

- JSON：完整机器契约和 Web UI 数据源；
- Markdown：风险路径、控制缺口、Unknown 和变化审查；
- DOT：Graphviz 图结构，可用于离线架构评审。

## 11. 验收与能力边界

当前自动化测试覆盖声明校验、四平面语义、证据升级、证据防降级、证据连续性、图指纹、图 diff、风险 diff、权限扩张、控制变化、Agent 回填、CLI、API、持久化和导出。

仍未完成正式效果测评、通用云 IAM 继承解析、动态基础设施发现和自动 Runtime Trace 回填。这些属于准确率和适配器建设，不应通过 LLM 推断伪造。当前产品会把缺失信息暴露为 Unknown 或声明需求。
