# Agent 一键部署

将源码包交给 Codex、Claude Code 或其他具备终端权限的编程 Agent 后，可以直接发送这一句话：

> 请在当前仓库执行 `scripts/agent-one-click-deploy.ps1 -Agent codex`（Linux/macOS 执行 `sh scripts/agent-one-click-deploy.sh --agent codex`），完成 Docker 构建、启动本地 Web UI、安装 `vibe-sec` Skill，并把健康检查结果和访问地址返回给我。

## 完成内容

一键脚本会依次完成：

1. 检查 Docker CLI。
2. 创建默认 `projects/` 目录并以只读方式挂载到容器 `/workspace`。
3. 构建并启动 `api` 和 `web` 服务。
4. 将 `vibe-sec` Skill 安装到指定 Agent 的 Skill 目录。
5. 等待 `/api/health` 返回 200。
6. 输出本地 Web UI 地址，默认是 `http://localhost:8000`。

## 常用命令

Windows：

```powershell
scripts/agent-one-click-deploy.ps1 -Agent codex
scripts/agent-one-click-deploy.ps1 -Agent claude-code -Port 8010
scripts/agent-one-click-deploy.ps1 -Agent project -ProjectsPath D:\authorized-projects
scripts/agent-one-click-deploy.ps1 -Agent codex -LlmSecretFile C:\secrets\deepseek.key
```

Linux/macOS：

```bash
sh scripts/agent-one-click-deploy.sh --agent codex
sh scripts/agent-one-click-deploy.sh --agent claude-code --port 8010
sh scripts/agent-one-click-deploy.sh --agent project --projects /srv/authorized-projects
sh scripts/agent-one-click-deploy.sh --agent codex --llm-secret /run/secrets/deepseek.key
```

## 使用边界

- Web UI 只发布一个宿主机端口，API 仅在 Compose 内网访问。
- 项目目录默认只读挂载；普通审查不会修改源码。
- LLM Key 通过外部 secret 文件注入，不写入镜像、Skill 或项目状态。
- Skill 只负责接入和回送，安全判断、验证、证据和整改由平台后端负责。
- 动态验证和高权限整改仍需显式授权、Harness 沙箱和确认门。
