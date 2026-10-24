# VRTM：Vibe Coding 运行面威胁建模方法

> 版本：0.2  
> 日期：2026-07-22  
> 状态：产品化方法、实现契约与持续建模闭环

## 1. 目的

VRTM（Vibe Runtime Threat Modeling）是一套面向 Vibe Coding、Agentic Application、MCP 和 AI 工作流的持续威胁建模方法。

它借鉴微软威胁建模中的数据流图、信任边界、STRIDE 和 SDL，但不把 AI 系统简化为普通数据处理系统。VRTM 将模型指令、委托权限、工具能力、记忆和生成产物作为一等安全对象。

VRTM 的目标不是生成一张装饰性架构图，而是回答：

1. 攻击者能够控制什么；
2. 控制内容如何进入系统；
3. 内容如何影响模型、代码和自动化决策；
4. 身份和能力如何被委托；
5. 哪些敏感资产可以被触达；
6. 哪些控制存在、缺失或尚未验证；
7. 哪些结论是事实、推断、运行时观察或未知；
8. 一次代码变更如何改变系统风险。

## 2. 基本原则

### 2.1 图不等于结论

节点和边必须有来源、证据等级和安全语义。不能根据同文件、同目录或命名相似就把两个对象声明为可达事实。

### 2.2 未知不等于安全

源码无法表示的部署身份、外部 MCP、运行时策略和生产权限必须进入 Unknown 或 Assumption，不能默认不存在。

### 2.3 指令也是控制面

进入模型上下文的外部内容不仅是数据，还可能改变模型决策、工具选择和参数。因此指令影响必须与数据流分开表达。

### 2.4 权限沿调用链传播

模型本身通常不直接拥有系统权限，但可以通过 Tool、MCP、浏览器、工作流 Token 和部署凭据获得代理能力。建模必须表示有效身份和委托能力。

### 2.5 风险必须可验证

每个风险假设应给出路径、缺失控制、假设、证据谓词和验证计划。模型或规则生成的假设不能直接成为确认漏洞。

### 2.6 持续建模

Vibe Coding 产物变化快。建模必须支持稳定 ID、图版本、变化比较、新风险、已缓解风险和权限扩大，而不是只在设计阶段执行一次。

## 3. 四平面模型

### 3.1 Data Plane

描述输入、数据处理、持久化和输出：

```text
External Input → Entry → Code → Storage / Browser / External Service
```

主要风险包括注入、数据泄露、越权访问、数据篡改和不安全输出。

### 3.2 Instruction Plane

描述内容如何影响 Prompt、模型、工具选择和自动化决策：

```text
External Content → Context / Prompt → Model Decision → Tool Selection
```

主要风险包括直接和间接提示注入、工具描述注入、上下文污染和不可信模型输出。

### 3.3 Authority Plane

描述身份、权限、能力和审批如何传播：

```text
Caller Identity → Model / Workflow → Tool / MCP → Privileged Asset
```

主要风险包括过度代理、工具越权、MCP 授权缺失、Token 代理和缺失人工审批。

### 3.4 Artifact Plane

描述代码、配置、依赖、记忆和生成物如何持久化及进入部署：

```text
Generated Content → Source / Memory / Build Artifact → Deployment
```

主要风险包括记忆污染、生成代码缺陷、供应链污染、工作流注入和部署篡改。

一条关系可以同时属于多个平面。例如外部检索内容进入模型，同时属于 Data Plane 和 Instruction Plane。

## 4. 图本体

### 4.1 主体

- `external_actor`
- `human_operator`
- `coding_agent`
- `runtime_agent`
- `service_identity`
- `external_service`

### 4.2 接口和执行

- `entry_point`
- `workflow`
- `code_block`
- `browser_sink`

### 4.3 AI 上下文

- `external_content`
- `prompt`
- `model`
- `memory`
- `retriever`

### 4.4 能力

- `tool`
- `mcp_capability`
- `code_execution`
- `deployment_capability`

### 4.5 资产

- `storage_asset`
- `privileged_asset`
- `secret_asset`
- `source_artifact`
- `deployment_asset`

### 4.6 控制和边界

- `permission`
- `security_control`
- `approval_control`
- `policy_gateway`
- `trust_boundary`

首版实现继续兼容现有节点类型，并通过 `entity_group`、`control` 和 `asset_type` 属性补充本体语义。

## 5. 关系语义

推荐的规范关系包括：

- `supplies_data`
- `influences_instruction`
- `invokes`
- `delegates_authority`
- `reads`
- `writes`
- `persists_to`
- `loads_from`
- `authenticates_as`
- `crosses_boundary`
- `renders`
- `navigates`
- `builds`
- `deploys`
- `approves`
- `filters`
- `governs`

现有实现中的 `influences`、`can_invoke`、`accesses` 等 relation 暂时保留，使用 `semantic_relation` 映射到规范关系，以保持审计和威胁规则兼容。

每条边至少包含：

- `flow_planes`；
- `semantic_relation`；
- `security_meaning`；
- `evidence`；
- `trust_crossing`；
- 可解析时的身份、权限、验证和审批信息。

## 6. 证据等级

| 等级 | 含义 |
| --- | --- |
| `declared` | 来自项目声明或配置，但未由实现确认 |
| `static_observed` | 从源码或结构化配置直接观察 |
| `inferred` | 根据框架语义、有限共址或调用关系推断 |
| `runtime_observed` | 在受控运行环境中观察 |
| `verified` | 已通过专门验证谓词确认 |
| `unknown` | 当前证据无法判断 |

证据对象包含来源类型、置信度、文件位置、提取器和说明。置信度不能替代证据等级。

## 7. 控制模型

控制不能只表示“代码中出现了鉴权关键字”。VRTM 将控制表达为：

```text
Control Type
+ Enforcement Point
+ Enforcement State
+ Protected Relation / Asset
+ Evidence Level
+ Effectiveness
+ Verification State
```

控制强度使用离散状态：

- `strong`：存在强制执行且有运行时或验证证据；
- `implemented`：源码或配置中观察到控制；
- `partial`：只覆盖部分路径或存在绕过风险；
- `missing`：路径中未发现所需控制；
- `unknown`：无法从当前证据判断。

首版实现从 Permission、Trust Boundary、确认机制、授权字段和访问控制中生成控制摘要；控制有效性仍需 Verification 阶段确认。

## 8. 风险假设

VRTM 风险假设由以下部分组成：

```text
Technique
+ Source
+ Attack / Influence Path
+ Boundary Crossings
+ Target Asset
+ Flow Planes
+ Control Gaps
+ Assumptions
+ Evidence Predicates
+ Risk Factors
```

风险因素分开表达：

- `impact`；
- `exploitability`；
- `evidence_confidence`；
- `control_strength`。

首版不生成看似精确的单一数字风险分数。`severity` 用于排序，`confidence` 用于表达证据可信度，两者不能混用。

## 9. Technique Catalog

每个内部 Technique 包含：

- 稳定 Technique ID；
- 名称、类别和描述；
- 适用节点；
- 四平面；
- 图路径模式；
- 默认影响等级；
- 验证策略；
- 外部框架映射。

外部映射包括：

- Microsoft STRIDE；
- MITRE ATT&CK / ATLAS；
- CWE / CAPEC；
- OWASP LLM / Agentic Top 10；
- 后续可增加 NIST AI RMF 和 Microsoft SDL Practice。

内部 Technique 是执行规则的稳定主键，外部框架只作为解释和互操作映射。

## 10. 建模流程

```text
1. Scope
2. Discover
3. Model
4. Analyze
5. Investigate
6. Verify
7. Evolve
```

### Scope

定义项目、环境、主体、资产、外部系统和分析边界。

### Discover

从源码、框架、配置、MCP、工作流和用户声明中抽取运行面对象。

### Model

生成四平面关系、信任边界、控制、资产、证据等级、Assumption 和 Unknown。

### Analyze

Technique 使用图路径模式产生 Risk Hypothesis，而不是直接确认漏洞。

### Investigate

Audit Agent 通过源码、语义路径、图查询和可选扫描器补充支持与反证。

### Verify

Verification Agent 根据证据谓词执行静态、动态、Fuzz、浏览器或隔离环境验证。

### Evolve

修复或代码变化后生成图差异，识别新增、删除、变化节点和关系，以及新出现和已缓解风险。

## 11. 覆盖率和未知区域

VRTM Coverage 至少报告：

- 文件考虑、解析和失败数量；
- 节点及类型数量；
- 边及四平面数量；
- 各证据等级数量；
- 已建模和未建模节点类型；
- 未知授权、身份、控制和部署信息；
- 推断关系数量；
- 风险假设数量；
- 需要运行时验证的路径数量。

覆盖率用于约束产品声明，不能直接解释为安全分数。

## 12. 图版本和差异

图使用稳定节点 ID 和稳定边 ID。每次构建产生内容指纹，并可与前一版本比较：

- `added_nodes`
- `removed_nodes`
- `changed_nodes`
- `added_edges`
- `removed_edges`
- `changed_edges`

后续将在威胁模型层继续产生：

- `new_hypotheses`
- `resolved_hypotheses`
- `changed_hypotheses`
- `authority_expansion`
- `new_boundary_crossings`

## 13. 可视化视图

同一图应支持不同投影，而不是强制展示一张总图：

1. Runtime Surface View；
2. Data Flow View；
3. Instruction Influence View；
4. Authority and Capability View；
5. Artifact and Deployment View；
6. Focused Risk Path View；
7. Graph Diff View。

可视化必须允许按证据等级、四平面、严重性、Technique 和信任边界过滤。

## 14. 声明与观察

完整模型最终由三类来源组成：

```text
Source Extraction
+ Project Declaration
+ Controlled Runtime Observation
```

首版实现以源码和结构化配置抽取为主。项目声明和运行时回填必须保留各自证据等级，不能覆盖或伪装为源码事实。

## 15. 当前实现边界

0722 首版实现目标：

- 四平面和规范关系；
- 节点和边证据等级；
- Permission 和 Boundary 控制摘要；
- Technique 外部映射；
- 风险因素和控制缺口；
- 覆盖率和 Unknown；
- 图内容指纹和版本差异；
- 支持按四平面投影的前端数据。

不在首版完成范围：

- 完整部署拓扑自动发现；
- 通用云资产和身份权限解析；
- 项目声明文件编辑器；
- 动态 Trace 自动回填；
- Technique 全量目录；
- 风险评分标定；
- Web UI；
- 正式方法论效果测评。

## 16. 智能体驱动的持续建模

VRTM 不是 Surface Agent 一次性生成、随后只读的静态产物。初始图是审查的输入，审查和验证过程取得的新证据也必须能够反向丰富图模型，并触发风险假设重算。

```text
确定性提取与项目声明
  -> 初始四平面图
  -> Technique 生成风险假设
  -> Audit Agent 调查 Unknown 和低置信路径
  -> 工具调用或受控验证取得证据
  -> 提交结构化 Graph Observation
  -> 校验并回填证据、控制状态和关系
  -> 重算 Coverage、Fingerprint 和 Risk Hypothesis
  -> 整改后生成 Graph Diff
```

### 16.1 职责边界

- `Surface Agent`：负责确定性抽取、稳定 ID、初始关系和覆盖率，不依赖 LLM 猜测事实。
- `Threat Model Analyzer`：根据 Technique 和图路径生成风险假设，不直接确认漏洞。
- `Audit Agent`：围绕风险路径调用源码、语义追踪和配置工具，补充支持证据与反证。
- `Verification Agent`：执行受控静态、动态或隔离环境验证，满足证据谓词后才能产生 `verified` 观察。
- `Remediation/Retest Agent`：修复后重新建模和验证，用图差异判断权限扩张、新边界穿越和风险消除。

### 16.2 Graph Observation 约束

智能体不能直接任意改写事实图。每条回填记录至少包含：

- 目标节点或边的稳定 ID；
- 提交 Agent 和产生证据的 Tool；
- Observation 类型、属性和时间；
- Evidence Level、Evidence Reference 和 Confidence；
- 支持或反驳的 Risk Hypothesis；
- 应用前后的 Graph Fingerprint。

只有源代码、结构化配置、工具输出或受控运行结果可以改变事实属性。纯 LLM 判断可以提出 `inferred` 关系或调查建议，但不能标记为 `static_observed`、`runtime_observed` 或 `verified`。`verified` 必须引用 Verification Agent 的证据谓词和正/负对照结果。

### 16.3 重算规则

图观察应用后必须重新执行以下步骤，避免局部状态不一致：

1. 校验目标 ID、关系语义、证据等级和来源；
2. 更新控制摘要和 Unknown；
3. 重算四平面 Coverage；
4. 重算 Risk Hypothesis，但保留稳定 Hypothesis ID；
5. 生成新 Fingerprint 和 Graph Diff；
6. 将新增、消除和证据等级变化回送开发上下文。

这一机制的价值不是让 LLM 自由生成更复杂的图，而是让审查过程逐步减少 Unknown、提升路径证据质量，并保留所有结论如何形成的审计轨迹。

## 17. 产品实现契约

### 17.1 独立建模入口

VRTM 可以脱离完整漏洞审计独立运行，不依赖 LLM、Docker 或传统扫描器：

```powershell
vibe-sec model-init <project-path>
vibe-sec model <project-path> --format json
vibe-sec model <project-path> --format markdown --output vrtm.md
vibe-sec model <project-path> --format dot --output vrtm.dot
```

`model-init` 创建 `.vibe-sec/vrtm.yaml`。声明文件只用于描述源码无法可靠观察的部署身份、外部服务、Agent、Memory、Retriever、Secret、Approval 和 Deployment，不得把推断内容伪装成运行事实。

### 17.2 项目声明

声明 Schema 为 `vibe-sec.vrtm.declaration.v1`，包含：

- `scope`：环境、租户和建模边界；
- `nodes`：带稳定 `key` 的运行实体；
- `edges`：引用稳定 key 或节点 ID 的规范关系；
- `assumptions`：无法验证但风险分析必须显式依赖的条件；
- `exclusions`：有责任人和理由的建模排除项。

未知节点类型、未知关系、重复 key、非法平面、越界置信度和未解析引用都会产生明确错误或诊断。含图完整性错误的模型不会写入版本库。

### 17.3 版本存储

默认存储目录为 `.vibe-sec/vrtm/`：

```text
.vibe-sec/vrtm/
  latest.json
  snapshots/<fingerprint-prefix>.json
```

快照以图内容指纹寻址并原子写入。相同图不会创建重复版本。`latest.json` 指向最后接受的完整模型；无效模型不覆盖基线。

### 17.4 安全变化门禁

VRTM 对相邻模型输出：

- 新增、移除和变化节点；
- 新增、移除和变化关系；
- 新增、消除和变化风险假设；
- Hypothesis 状态变化；
- Authority Expansion；
- 新 Trust Boundary Crossing；
- 新 Privileged Asset；
- Control Regression / Improvement。

以下命令用于 CI 或发布前门禁：

```powershell
vibe-sec model <project-path> --fail-on-review
```

退出码 `2` 表示存在需要人工安全审查的权限扩大、边界变化、特权资产或控制退化。它不等价于确认漏洞。

### 17.5 API 与前端契约

- `POST /api/vrtm/models`：构建或演化模型；
- `GET /api/vrtm/models/latest`：读取项目最新模型；
- `GET /api/vrtm/models`：列出不可变快照；
- `graph.visualization.views`：四平面过滤投影；
- `risk_paths`：可高亮的风险路径；
- `coverage`：证据、Unknown 和平面覆盖；
- `security_change_analysis`：变化审查入口。

### 17.6 当前能力边界

产品实现已经具备源码和结构化配置抽取、项目声明、四平面图、14 类复合 Technique、Observation 回填、风险生命周期、版本 diff、CLI、Skill 和 API 契约。

仍需通过正式数据集测量抽取准确率、路径有效率和误报率；云 IAM 的继承策略、动态基础设施拓扑和运行时 Trace 仍依赖项目声明或专用适配器。系统必须把这些内容保留为 Unknown，不得据此声称项目安全。
