# Changelog

本项目的所有显著变更记录于此。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

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
