# Changelog

本项目的所有显著变更记录于此。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.14.0] — 2026-10-26

### 修复

- **可见性/可审计性贯穿瘦身报告**：`exclusion` 排除回显与 `suppressed_findings` 抑制概要（类型/位置/原因）不再因默认瘦身输出而丢失——ignore 文件来自被审计项目的对抗边界在任何报告形态下都必须可见

### 新增

- **LLM 语义通道验收工具** `scripts/cve_replay_llm.py`：在 CVE 回放靶场跑 LLM 审计并按行级标准评分；静态可命中目标（mistune/launch-editor）作为对照组，对照未全部命中时结论标记 `inconclusive`（本次 LLM 运行不足以为语义结论背书）；缺凭据退出码 2，模型故障标记 error 不中断其余目标

## [0.13.0] — 2026-10-26

### 新增

- **真实 CVE 回放基线翻牌 0/3 → 2/3**：
  - mistune（CWE-22）：路径遍历门控新增第三形态——非请求污点（文档/模板/配置参数）经 `join(dirname(源), 变量)` 进入文件读取且窗口内无包含性校验（commonpath/is_relative_to/relative_to/startswith），校验缺失本身即信号
  - launch-editor（CWE-78）：命令注入新增 JS `child_process.exec` 汇点与 Windows CMD `^` 转义白名单缺 `%` 的绕过形态
  - serialize-javascript（CWE-79）保留 strict xfail：转义正则的语义绕过静态原理性不可见——"看着已修复实则可绕过"的 false positivity 标本，归 LLM 语义审查通道职责
- 两类新模式经基准门禁验证零误报引入（safe 集仍 0 误报，内置靶场 100% 召回无漂移）

## [0.12.0] — 2026-10-26

### 新增（感谢 @shangjian2023 的五项贡献）

- **tree-sitter 段错误修复**：原生 `start_point/end_point` 在部分语法树上崩溃（Windows 实测 SIGSEGV），统一改为字节偏移换算行号；附最小崩溃样本回归测试。修复后 mem0 全库审计从 2/2 崩溃到 109s/403 findings，TS 泳道真正跑通
- **CVE 回放召回基线**：vendor 三个真实漏洞版本快照（mistune/serialize-javascript/launch-editor，保留上游许可），行级命中标准 = 修复 hunk ±8 行；当前基线 0/3 以 strict xfail 锁定——检测器补上召回即翻 XPASS 强制更新基线
- **审计 JSON 报告默认瘦身**：真实仓库全量 JSON 可达数百 MB，默认输出紧凑报告，完整结果归档本地 ArtifactStore 并以 full_result_ref（sha256）引用；`--full-result` 恢复旧行为，retest 自动经 ref 回读
- **项目路径排除**：默认排除 `*.min.js`/`*.map`/`dist`，项目内 `.vibe-secignore` 与 CLI `--exclude` 可叠加；生效模式与 ignore 文件存在性随结果回显（维护者补全——恶意仓库携带全排除文件时对使用者可见）
- **Finding 级误报抑制**：本地抑制库（类型+路径±5 行），合并阶段过滤且 `suppressed_findings` 回显留痕；抑制只认工具侧存储，被审计源码永不参与

## [0.11.0] — 2026-10-26

### 新增

- **失败任务一键重试**：`POST /api/audit-tasks/{id}/retry` 按原参数（use_llm/output_format 已随任务持久化）重建 PENDING 任务；进程重启导致的 FAILED 任务恢复从"手动新建"缩短为一键重试，LLM 配置按当前激活模型重新解析
- **英文文档 README.en.md**：完整英文版（定位、核心设计、快速开始、Code Scanning/整改 PR 接入、基准说明），中英双语互链
- LLM 配置解析提取为共用助手（创建与重试共用同一 422 校验语义）

## [0.10.0] — 2026-10-26

### 新增

- **自动修复 PR 执行器** `scripts/open_remediation_pr.py`：把审计产出的 RemediationBundle 组装成 GitHub PR（正文即 ai_patch_prompt + 修改约束 + 验收清单 + 复测计划，附 CWE 直链；Bundle 落盘 `.seismoscope/remediation/`），`--split` 每漏洞单独成 PR，`--dry-run` 无副作用预览；修复指令由此进入标准 GitHub 协作流，可被 AI 编码助手直接消费

## [0.9.1] — 2026-10-26

### 变更

- PyPI 分发名定为 **seismoscope**（首个 PyPI 发布版本；曾用分发名 vibe-sec-platform 未发布过）
- CLI 新增 `seismoscope` 等价命令（`vibe-sec` 保持不变）
- SARIF tool driver 版本号读取改为新分发名

## [0.9.0] — 2026-10-26

### 新增

- CWE/OWASP 映射：SARIF 告警携带 CWE 编号、标准标签与 helpUri 直链
- CI 能力防回退门禁：每次 PR 自动运行靶场召回基准并与基线对比，检测能力回退即失败
- CI Python 版本矩阵扩展至 3.11 / 3.12 / 3.13
- PyPI Trusted Publishing 发布工作流（OIDC 短期凭证，无长期 Token）
- SECURITY.md 安全策略、CHANGELOG.md、Issue/PR 模板、文档索引与目录归位（docs/competition、docs/progress）

### 变更

- 比赛材料（作品简介、系统设计文档）与进度快照分别归档至 `docs/competition/`、`docs/progress/`

## [0.8.0] — 2026-10-26

### 新增

- SARIF 2.1.0 输出（`vibe-sec audit --format sarif`），可直接上传 GitHub Code Scanning；附示例工作流 `docs/examples/seismoscope-code-scanning.yml`
- 真实 VAmPI 外部靶场验证：6 个已知漏洞中 4 个静态可映射类型全部命中、零误报

### 修复

- 字典下标带引号键的密钥赋值（`config['SECRET_KEY'] = 'random'`）检测缺口
- 特权字段成员检查/下标访问形态（`'admin' in request_data`）检测缺口

## [0.7.0] — 2026-10-26

### 新增

- 靶场召回/误报基准脚本 `scripts/benchmark_recall.py`（`--compare` 防回退、`--project` 接入外部靶场）
- 项目更名候风 Seismoscope，仓库迁移至 `dxz0069/seismoscope`

### 修复

- `sk-` 前缀密钥与 `:` 赋值形态、MCP 字典语法通配权限、f-string 反射型 XSS 三处检测缺口
- 相邻不同密钥因脱敏证据相同被错误合并的去重缺陷
- Windows 传统控制台（cp1252）中文输出编码错误

## [0.6.0] — 2026-10-26

### 新增

- tree-sitter 解析器统一网关：下载失败按语言负缓存，受限网络优雅降级；`VIBE_SEC_TREE_SITTER_CACHE` / `VIBE_SEC_DISABLE_TREE_SITTER` 环境变量；doctor/setup 集成
- SQL 注入补齐调用外拼接与 % 中置格式化形态；新增 mass_assignment、plaintext_password_comparison 检测并接入验证白名单

## [0.5.0] — 2026-10-24

### 首次发布

- 12 阶段确定性编排、五通道并行审计、VRTM 四平面运行面建模、三态验证、RemediationBundle 结构化整改回送
- 本地 CLI / Docker Compose 部署、MIT License、CI 双平台测试
