# 安全策略 / Security Policy

## 支持版本 / Supported Versions

| 版本 | 支持状态 |
|---|---|
| 0.9.x | ✅ 支持 |
| < 0.9 | ❌ 不支持 |

## 报告漏洞 / Reporting a Vulnerability

**请不要通过公开 Issue 报告安全漏洞。**

请使用 GitHub 私有漏洞报告（仓库 Security 标签页 → Report a vulnerability），或联系维护者邮箱。我们会在 **3 个工作日内**确认收到，**7 个工作日内**给出初步评估。

报告内容建议包含：受影响版本、复现步骤/最小化 PoC、影响评估。请给我们合理的披露窗口（建议 90 天）；修复发布后会在 Release Notes 中致谢（除非你要求匿名）。

## 审查范围说明 / Scope Notes

候风 Seismoscope 本身是一个安全审查工具，设计上会处理不可信输入（被审查项目的源码）。已知且接受的边界：

- 密钥类发现的内容在 CLI/API 输出中统一脱敏为 `[REDACTED]`，仅输出指纹；
- 动态验证与 PoC 执行默认关闭，需显式授权（`--allow-poc` 等开关）且仅在本地受控环境执行；
- 审查不可信项目时，请在隔离环境（容器/虚拟机）中运行本工具——工具读取任意源码，恶意源码可能包含针对开发环境的攻击载荷；
- 默认 Compose 部署不挂载 Docker Socket，容器扫描器应由已授权的宿主机 Runner 执行。

## 自身安全设计 / Security by Design

- 确定性编排：LLM 只能调用只读工具取证，不能变更执行环境；
- 推理护栏（ReasoningGuard）：阻止"我认为安全"式的无证据结论；
- 三态验证：结论必须携带证据链，证据不足保留 `needs_evidence`；
- `doctor` 只报告凭据是否配置，不读取、不输出密钥值。
