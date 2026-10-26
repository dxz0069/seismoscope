# 多靶场能力测试报告（2026-08-02）

## 1. 结论

本轮完成了 Vibe Sec Platform 在本地靶场副本上的第一轮多靶场能力基线：

| 能力 | 结论 | 证据 |
| --- | --- | --- |
| Python/Flask 静态审查 | 已验证 | 合成 Web/Agent fixture、VAmPI |
| OpenAPI/Connexion 运行面提取 | 已验证 | VAmPI 提取 14 个 API 入口 |
| TypeScript/Node 静态审查 | 已验证 | Juice Shop 提取 247 个入口、495 个代码块 |
| VRTM 运行面建模 | 已验证，但大型项目仍需继续降噪和聚合 | 三个基线产物均包含 VRTM 图和风险上下文 |
| Agent/MCP 风险识别与整改闭环 | 已验证一个受控案例 | command injection 包完成审批、回归、关闭 |
| LLM 整改与复测闭环 | 已验证两个受控案例 | VAmPI SQLi、Juice Shop B2B evaluator 均已关闭 |

这不是“检测率已达标”的结论。VAmPI 的六个带标签弱点中，本次无 LLM 静态基线仅命中 SQL 注入 1 项；Juice Shop 的 98 个候选中有 68 个因验证预算未处理。平台已经具备跨语言建模、候选发现、整改包和复测闭环能力，但语义业务漏洞识别和大项目候选降噪仍是当前主要短板。

## 2. 测试范围与规则

- 范围：工作区内的靶场源码副本、测试 fixtures、已有的本地复测报告。
- 不在范围：远程靶场写入、生产系统、凭据测试、批量扫描、网络利用。
- 本轮基线：`--no-model-store`、未配置 LLM、未启动服务、未调用容器扫描器或网络。
- 动态证据：只复用先前在隔离本地副本上执行的受控整改复测，不将静态候选表述为已证实漏洞。
- 停止条件：CLI 非零退出、候选状态不守恒、意外启动服务、靶场源码发生写入。

当前环境的 `python main.py doctor` 返回 Docker 与 focused-tools、trivy、nuclei 镜像就绪；codeql 为可选且未安装。该就绪检查不代表这些工具已在本轮基线中执行。

平台回归测试于本轮结束前重新执行：`python -m pytest -q` 返回 `224 passed, 1 skipped in 115.54s`。该结果验证平台自身测试契约，不替代靶场漏洞验证。

## 3. 可复现输入与命令

| 目标 | 固定快照标识 | 审计产物 |
| --- | --- | --- |
| 合成 Web + Agent/MCP fixture | `vulnerable_app.py`: `44890DE40D04E08D0A1A7A713F8DE630FF969E64E2C561C5579FC2292703D8BF`; `vulnerable_agent_app.py`: `E25402EBED49CF720A533D9E1F2482DEA5E6170962BDDCA5A0E263883D6FB6E4` | `.lab-cache/benchmarks-v1/fixture/audit-no-llm.json` |
| VAmPI | 源码归档 SHA-256: `995BBF23DF2035EC34E27EAFAF1C8F321C4799E4B44FE9A84B8742A29D7FEA24` | `.lab-cache/benchmarks-v1/vampi/audit-no-llm.json` |
| OWASP Juice Shop | 源码归档 SHA-256: `7FD24BA133E3127AAF21D7043D721FB4D09BF09751A5EED0496EEDCCCBD6F68D` | `.lab-cache/benchmarks-v1/juice-shop/audit-no-llm.json` |

三项基线使用同一命令形态：

```powershell
python main.py audit <target> --format json --output <artifact> --session-dir <sessions> --no-model-store
```

实际执行的目标与输出为：

```powershell
python main.py audit tests/fixtures --format json --output .lab-cache/benchmarks-v1/fixture/audit-no-llm.json --session-dir .lab-cache/benchmarks-v1/fixture/sessions --no-model-store
python main.py audit .lab-cache/VAmPI --format json --output .lab-cache/benchmarks-v1/vampi/audit-no-llm.json --session-dir .lab-cache/benchmarks-v1/vampi/sessions --no-model-store
python main.py audit .lab-cache/juice-shop-source --format json --output .lab-cache/benchmarks-v1/juice-shop/audit-no-llm.json --session-dir .lab-cache/benchmarks-v1/juice-shop/sessions --no-model-store
```

审计产物均已用 Node JSON 解析器复核为有效 JSON；`verification_summary.conserved` 均为 `true`。

## 4. 基线结果

| 靶场/样本 | 规模与运行面 | 合并候选 | 验证状态 | 关键结果 |
| --- | --- | ---: | --- | --- |
| 合成 Web + Agent/MCP fixture | VRTM 53 节点 / 70 边 / 1 条风险假设 | 16 | 14 `needs_evidence`，2 `rejected` | 命令注入、代码注入、SQL 注入、路径遍历、提示词注入、过度代理、secret leak 均出现候选 |
| VAmPI | 14 API 入口；VRTM 80 节点 / 104 边 | 1 | 1 `needs_evidence` | 在 `models/user_model.py:72` 命中 SQL 注入；说明 OpenAPI/Connexion 入口已被建模 |
| Juice Shop | 247 入口、495 代码块；VRTM 1161 节点 / 418 边 | 98 | 29 `needs_evidence`，68 `not_reviewed`，1 `rejected` | `routes/b2bOrder.ts:23` 命中 critical 代码注入候选 |

合成 fixture 的价值是回归面覆盖，不作为真实项目的精确率指标。该样本中存在重复或过宽的提示词注入候选，也出现了疑似 secret leak 误报，因此不能用其 16 个候选直接计算精确率。

Juice Shop 的候选类型分布为：prompt injection 60、MCP insecurity 13、secret leak 10、insecure deserialization 5、XSS 4、code injection 3、SSRF 2、SQL injection 1。大部分候选仍处于验证预算外，当前数字只代表待审优先级队列，不代表已确认漏洞数量。

## 5. VAmPI 带标签弱点映射

VAmPI 是本轮唯一具有明确六项已知弱点清单的固定靶场。本表基于源码副本逐项核对，作为本次基线的人工标签映射。

| 标签 | 源码锚点 | 无 LLM 基线状态 | 说明 |
| --- | --- | --- | --- |
| SQL 注入 | `models/user_model.py:72`，字符串拼接后执行 SQL | 命中，`needs_evidence` | 候选 `cluster-49eba828722d6af1`，high |
| 弱 JWT 签名密钥 | `config.py:13`，`SECRET_KEY = 'random'` | 未命中 | 需要识别敏感配置名与弱值语义 |
| 注册时管理员自赋权 | `api_views/users.py:60-66` | 未命中 | 需要请求字段到权限字段的数据流/业务规则推理 |
| 调试接口数据暴露 | `api_views/users.py:24-25`，并经 `json_debug` 返回密码字段 | 未命中 | 入口已提取，但缺少敏感响应字段识别 |
| BOLA/IDOR | `api_views/books.py:50-58`，按书名查询未校验所有者 | 未命中 | 需要认证主体与资源所有者关联分析 |
| 明文密码比较 | `api_views/users.py:93` | 未命中 | 需要密码存储与认证语义规则 |

按这六个去重标签计算，本次固定快照的静态召回是 1/6（16.7%）。这是当前规则/建模流水线在该靶场上的基线，不可外推为平台整体召回率；也不构成精确率结论。

## 6. LLM 辅助审查复测

LLM 辅助路径使用真实 `deepseek` Provider、`deepseek-v4-flash` 模型、`https://api.deepseek.com` OpenAI 兼容端点和只读的本地 VAmPI 副本。测试限制为 2 个候选复核、2 个验证会话、每会话最多 4 轮；未启动靶场、未启用动态工具、未写入目标 VRTM。

| 项目 | 结果 |
| --- | --- |
| Provider 配置 | 已启用真实 Provider，ReAct 审查与验证开关均为 `true` |
| Provider 调用 | 旧配置与当前 v4 配置均被服务端认证拒绝，未获得任何 LLM 审查内容 |
| 静态候选保护 | SQL 注入候选保持为 1 个 `needs_evidence`，未被清空或误拒绝 |
| 状态守恒 | `total_candidates=1`，`needs_evidence=1`，`conserved=true` |
| LLM 状态 | 1 个 ReAct 审查降级，原因只记录为 `authentication_failed` |

本次测试还修复了 LLM 失败降级路径：Provider 认证、超时、限流或权限失败不会再丢弃静态候选；未完成的 ReAct 会话只能产生 `needs_evidence`，不能把候选错误标为拒绝。服务端错误原文不会进入审计证据或日志。DeepSeek 默认配置已更新为 v4 OpenAI 兼容端点，并有模型/端点契约测试。回归覆盖位于 `tests/test_llm_failure_degradation.py` 与 `tests/test_llm_model_configuration.py`，定向测试通过 `25 passed`；完整套件最终通过 `224 passed, 1 skipped`。

由于当前开发密钥被 Provider 拒绝，本轮没有继续发起 Juice Shop 和 Agent/MCP 的无效 LLM 请求。三靶场的历史真实 LLM 闭环证据仍见下一节；要完成新的全量 LLM 横向基线，需要 Provider 接受的有效开发凭据。

## 7. 已完成的整改闭环证据

以下三个闭环均来自隔离本地副本，且都有明确审批、VRTM 绑定和 3/3 回归通过。它们用于验证工作流闭环，不影响上节“脆弱源码快照”的基线结果。

| 场景 | RunSession | 整改包 | 结果 | 复测报告 |
| --- | --- | --- | --- | --- |
| Agent/MCP command injection | `run-3be84ceab7e14d5f` | `REMEDIATION-cluster-e6638b678b098573` | closed=1, open=0, 3/3 | `.lab-cache/results/agent-mcp-closure-v4-retest.json` |
| VAmPI SQL injection | `run-4d944501145b449b` | `REMEDIATION-cluster-49eba828722d6af1` | closed=1, open=0, 3/3 | `.lab-cache/state-llm-vampi-v2/vampi-sql-injection-retest-final.json` |
| Juice Shop B2B evaluator | `run-2528bbc8947a4a57` | `REMEDIATION-cluster-2b4e565d4c1d4a98` | closed=1, open=0, 3/3 | `.lab-cache/state-llm-juice-v5/juice-b2b-retest-final.json` |

Juice Shop 脆弱快照中的命中点为 `routes/b2bOrder.ts:23`，即 `vm.runInContext('safeEval(orderLinesData)', ...)`。闭环副本的复测成功不应被误读为脆弱快照已经修复。

## 8. 能力边界与后续门槛

已证明的能力：

1. Python、TypeScript、OpenAPI/Connexion 项目可进入统一 VRTM 运行面。
2. 静态发现能生成带源码锚点、证据等级、验证状态和整改包的候选。
3. 高风险案例可通过审批门、受控修改和回归复测形成关闭状态。

尚未通过的能力门槛：

1. VAmPI 的弱密钥、BOLA、管理员自赋权、敏感调试响应和明文认证比较没有被当前基线识别。
2. Juice Shop 的 98 个候选仍需去重、严重度排序、聚合为可操作风险路径，尤其是 prompt injection/MCP 类候选。
3. 当前没有人工标注的 Juice Shop 全量 Ground Truth，无法计算其精确率/召回率。
4. 本轮未运行传统扫描器或 AutoCVE，因此不应作横向能力优劣结论。
5. 当前命令行环境未配置 LLM 凭据；历史 LLM 闭环报告是已存档证据，不能替代本轮无 LLM 基线。

## 9. 下一阶段

多靶场第一轮能力测试至此完成，结论是“工作流和跨栈建模可用，但检测质量尚未达标”。进入横向对比前，应先固定：每个靶场的 Ground Truth 标签、候选去重规则、统一严重度映射、动态验证预算和统计口径。随后才执行传统工具与 AutoCVE 的同版本、同快照、同范围对比。
