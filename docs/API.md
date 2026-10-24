# Vibe Sec Platform API 文档

## 概述

Vibe Sec Platform 提供 RESTful API，支持项目管理、审计任务、结果查询和插件管理。

**Base URL**: `http://localhost:8000`

## 快速开始

### 启动 API 服务器

```bash
python -m api.server
```

或使用：

```bash
python -c "from api import start_server; start_server()"
```

API 默认仅监听本机回环地址 `127.0.0.1:8000`。项目、审计任务、发现项、整改包和验证会话保存在仓库的 `.vibe-sec/api-state.sqlite3`；可通过 `VIBE_SEC_API_DB_PATH` 指定其他本地路径。

### 启动本地 Web UI

```bash
cd frontend-v2
npm run dev
```

默认访问地址为 `http://127.0.0.1:4174`。Vite 仅将 `/api` 代理到本机 `http://127.0.0.1:8000`；远程靶场不是平台控制面的一部分。

### 访问 API 文档

启动服务器后，访问：
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## API 端点

### 项目管理

#### 创建项目

```http
POST /api/projects
Content-Type: application/json

{
  "name": "My Project",
  "path": "/path/to/project",
  "description": "Project description",
  "audit_scope": {
    "web_vulns": true,
    "agent_vulns": true,
    "secret_leaks": true
  }
}
```

**响应**:

```json
{
  "id": "uuid",
  "name": "My Project",
  "path": "/path/to/project",
  "description": "Project description",
  "audit_scope": {
    "web_vulns": true,
    "agent_vulns": true,
    "secret_leaks": true
  },
  "created_at": "2026-07-20T10:00:00",
  "updated_at": "2026-07-20T10:00:00"
}
```

#### 列出项目

```http
GET /api/projects
```

#### 获取项目详情

```http
GET /api/projects/{project_id}
```

#### 删除项目

```http
DELETE /api/projects/{project_id}
```

### 审计任务

#### 创建审计任务

```http
POST /api/audit-tasks
Content-Type: application/json

{
  "project_id": "uuid",
  "use_llm": false,
  "output_format": "markdown"
}
```

**响应**:

```json
{
  "id": "task-uuid",
  "project_id": "project-uuid",
  "status": "pending",
  "created_at": "2026-07-20T10:00:00",
  "started_at": null,
  "completed_at": null,
  "findings_count": 0,
  "remediation_count": 0,
  "result": null,
  "error": null
}
```

#### 列出审计任务

```http
GET /api/audit-tasks
GET /api/audit-tasks?project_id=uuid
```

#### 获取任务详情

```http
GET /api/audit-tasks/{task_id}
```

#### 获取审计发现

```http
GET /api/audit-tasks/{task_id}/findings
```

**响应**:

```json
[
  {
    "id": "finding-uuid",
    "task_id": "task-uuid",
    "vulnerability_type": "sql_injection",
    "severity": "high",
    "confidence": 0.85,
    "title": "SQL 注入风险",
    "file_path": "app.py",
    "line_start": 42,
    "line_end": 42,
    "description": "检测到 SQL 注入漏洞",
    "evidence": [...]
  }
]
```

#### 获取整改包

```http
GET /api/audit-tasks/{task_id}/remediations
```

### 插件管理

#### 列出插件

```http
GET /api/plugins
```

**响应**:

```json
[
  {
    "name": "custom_sql_injection",
    "version": "1.0.0",
    "author": "VibeSec Team",
    "description": "自定义 SQL 注入检测规则",
    "plugin_type": "detection_rule",
    "enabled": true
  }
]
```

### 系统信息

#### 健康检查

```http
GET /api/health
```

**响应**:

```json
{
  "status": "healthy",
  "version": "0.5.0",
  "timestamp": "2026-07-20T10:00:00"
}
```

#### 系统统计

```http
GET /api/stats
```

**响应**:

```json
{
  "projects_count": 5,
  "tasks_count": 10,
  "completed_tasks": 8,
  "total_findings": 42,
  "cache_stats": {
    "memory": {
      "size": 100,
      "max_size": 1000,
      "hits": 500,
      "misses": 50,
      "hit_rate": 0.91
    }
  }
}
```

## 使用示例

### Python 客户端

```python
import requests

# 创建项目
response = requests.post("http://localhost:8000/api/projects", json={
    "name": "My Project",
    "path": "/path/to/project",
    "audit_scope": {
        "web_vulns": True,
        "agent_vulns": True,
        "secret_leaks": True
    }
})
project = response.json()
project_id = project["id"]

# 创建审计任务
response = requests.post("http://localhost:8000/api/audit-tasks", json={
    "project_id": project_id,
    "use_llm": False,
    "output_format": "markdown"
})
task = response.json()
task_id = task["id"]

# 等待任务完成
import time
while True:
    response = requests.get(f"http://localhost:8000/api/audit-tasks/{task_id}")
    task = response.json()
    if task["status"] in ["completed", "failed"]:
        break
    time.sleep(2)

# 获取审计结果
if task["status"] == "completed":
    response = requests.get(f"http://localhost:8000/api/audit-tasks/{task_id}/findings")
    findings = response.json()
    print(f"Found {len(findings)} vulnerabilities")
    
    response = requests.get(f"http://localhost:8000/api/audit-tasks/{task_id}/remediations")
    remediations = response.json()
    print(f"Generated {len(remediations)} remediation bundles")
```

### cURL 客户端

```bash
# 创建项目
curl -X POST http://localhost:8000/api/projects \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Project",
    "path": "/path/to/project",
    "audit_scope": {
      "web_vulns": true,
      "agent_vulns": true,
      "secret_leaks": true
    }
  }'

# 创建审计任务
curl -X POST http://localhost:8000/api/audit-tasks \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "PROJECT_ID",
    "use_llm": false,
    "output_format": "markdown"
  }'

# 获取审计结果
curl http://localhost:8000/api/audit-tasks/TASK_ID/findings
```

## 配置

### 环境变量

```bash
# API 服务器配置
API_HOST=0.0.0.0
API_PORT=8000

# 缓存配置
CACHE_MAX_SIZE=1000
CACHE_DEFAULT_TTL=3600

# LLM 配置
OPENAI_API_KEY=your-api-key
ANTHROPIC_API_KEY=your-api-key
```

## 错误处理

所有 API 错误都返回标准 HTTP 状态码和 JSON 错误信息：

```json
{
  "detail": "Error message"
}
```

常见错误码：
- 400: 请求参数错误
- 404: 资源不存在
- 500: 服务器内部错误

## 认证

当前版本（0.5.0）暂不支持认证。后续版本将添加 API Key 和 OAuth2 认证。

因此 API 默认只监听 `127.0.0.1`，CORS 默认只允许本地开发源。不要在没有反向代理认证、访问控制和目录隔离的情况下将服务暴露到网络。

## VRTM 运行面建模 API

VRTM API 只接受已经通过 `/api/projects` 注册的 `project_id`，不接受任意本地路径。显式声明文件也必须位于项目根目录内。

### 构建模型

```http
POST /api/vrtm/models
Content-Type: application/json

{
  "project_id": "PROJECT_ID",
  "declaration_path": ".vibe-sec/vrtm.yaml",
  "observations": [],
  "persist": true
}
```

返回 `vibe-sec.vrtm.result.v1`，包含四平面图、风险假设、Coverage、Unknown、图差异、风险差异和安全变化分析。

### 查询版本

```http
GET /api/vrtm/models/latest?project_id=PROJECT_ID
GET /api/vrtm/models?project_id=PROJECT_ID
```

模型快照存储在项目 `.vibe-sec/vrtm/` 中。含完整性错误的模型不会覆盖有效基线。
