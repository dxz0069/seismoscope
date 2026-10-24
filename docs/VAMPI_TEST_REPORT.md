# VAmPI 靶场测试报告

> 测试日期：2026-07-29
> 靶场：VAmPI（erev0s/VAmPI）— 基于 Connexion/OpenAPI 的 Python REST API
> 测试范围：全量审计（no-LLM）+ 6 项量化指标验证

---

## 一、靶场概况

| 项目 | 值 |
|------|-----|
| 源码 | https://github.com/erev0s/VAmPI |
| 框架 | **Connexion** (Flask + OpenAPI 3.0) |
| 语言 | Python 3 |
| 文件数 | 11 个 Python 源文件 |
| 路由定义 | `openapi_specs/openapi3.yml`（OpenAPI 规范驱动，非装饰器） |
| 运行端口 | 5000 (Flask debug mode) |
| 已知漏洞 | 6 个 (OWASP API Top 10) |

### 已知漏洞清单

| # | 漏洞 | 严重度 | 源码位置 | OWASP 分类 |
|---|------|--------|---------|-----------|
| 1 | SQL 注入 | HIGH | `api_views/books.py` 原始 SQL 拼接 | API8: Injection |
| 2 | 弱 JWT 签名密钥 | CRITICAL | `config.py:13` `SECRET_KEY = 'random'` | API2: Broken Authentication |
| 3 | 管理员自赋值 | HIGH | `api_views/users.py:60-62` 注册时可设 `admin=true` | API1: Broken Object Level Authorization |
| 4 | Debug 端点数据暴露 | HIGH | `api_views/users.py:24` `/users/v1/_debug` 泄露所有用户数据 | API3: Excessive Data Exposure |
| 5 | IDOR (不安全直接对象引用) | HIGH | `api_views/books.py:53` 无所有权检查即可读取任意书籍 | API1: Broken Object Level Authorization |
| 6 | 明文密码比较 | MEDIUM | `api_views/users.py:93` `== user.password` 无哈希 | API2: Broken Authentication |

---

## 二、6 项量化指标验证

### GOAL 1: 图谱覆盖 — ⚠️ 部分达标

```
图节点: 48 | 图边: 44 | 连通率: 77%

节点类型分布:
  code_block         35  ← 每个 Python 函数/类
  workflow            5  ← .yml 文件被识别为 GitHub Actions
  privileged_asset    5
  external_actor      1
  storage_asset       1
  trust_boundary      1

缺失的节点类型:
  entry_point         0  ← 所有路由在 OpenAPI YAML 中，未被提取！
  external_content    0
  prompt              0
  model               0
  tool                0
  browser_sink        0
  permission          0
  mcp_capability      0
```

**根因**: VAmPI 使用 Connexion 框架，路由通过 `openapi3.yml` 的 `operationId` 映射到 Python 函数，而非 Flask 标准 `@app.route()` 装饰器。`RuntimeSurfaceBuilder` 的 `_extract_python_function` 方法只识别装饰器路由（`@app.route`、`@app.get` 等），不解析 OpenAPI 规范。

**OpenAPI 路由格式示例**:

```yaml
paths:
  /users/v1:
    get:
      operationId: api_views.users.get_all_users
  /users/v1/_debug:
    get:
      operationId: api_views.users.debug
  /books/v1:
    get:
      operationId: api_views.books.get_all_books
```

**需修复**: `_extract_config` 或新增 OpenAPI extractor，解析 `paths.*.operationId` 生成 `PageEntry`。

---

### GOAL 2: 风险召回 — ❌ 严重不足 (17%)

```
已知漏洞:     6 个
实际检测:     1 个 (sql_injection)
召回率:       17%
```

| 漏洞 | 检测状态 | 漏检原因 |
|------|---------|---------|
| SQL 注入 | ✅ 检测 | `api_views/books.py` 的 f-string SQL 拼接被模式匹配 |
| 弱 JWT 密钥 | ❌ 漏检 | `SECRET_KEY = 'random'` 值仅 6 字符，`hardcoded_password` 正则要求 ≥4 字符引号字符串，但可能因非典型命名未匹配 |
| 管理员自赋值 | ❌ 漏检 | 业务逻辑漏洞，需数据流追踪 `request_data['admin']` → `User(admin=admin)` |
| Debug 端点暴露 | ❌ 漏检 | 路由 `/users/v1/_debug` 未被识别（Connexion 问题），因此该端点完全不可见 |
| IDOR | ❌ 漏检 | 需理解 "获取书籍时无所有权检查" 的语义，当前纯模式匹配无法检测 |
| 明文密码比较 | ❌ 漏检 | `== user.password` 需语义理解 |

---

### GOAL 3: 证据质量 — ⚠️ 有谓词但缺证据链

```
Verified: 0 | Needs Evidence: 1
```

唯一的 SQLi finding 有静态谓词，但因不在 `STATIC_CONFIRMABLE` 列表且无动态验证环境，保持 `needs_evidence`。

---

### GOAL 4: 误报控制 — ✅ 合格

```
Verified: 0 | Rejected: 0 | Needs Evidence: 1
```

未将静态推断直接标为已确认，无明确误报。

---

### GOAL 5: 回归基线 — ✅ 已建立

| 指标 | 基线值 |
|------|--------|
| 图指纹 | `bf29c676ec7a8e6f...` |
| 威胁假设 | 0 |
| 风险路径 | 0 |
| 图节点 | 48 |
| 图边 | 44 |
| 解析失败 | 0 |
| 提取器 | python_ast ✅, tree_sitter ✅, yaml ✅ |

---

### GOAL 6: 修复闭环 — ⏳ 待验证

当前阶段未执行修复→复测流程。

---

## 三、关键发现

### 发现 1: OpenAPI/Connexion 路由提取缺失

**影响**: 所有使用 OpenAPI 规范定义路由的框架（Connexion、FastAPI+OpenAPI、Flask-RESTX 等）都无法被完整建模。

**涉及代码**: `core/surface/runtime_surface.py:_extract_config` 和 `_extract_python_function`

**建议修复**: 
1. 在 `_extract_config` 中检测 OpenAPI YAML/JSON（`openapi` 字段 + `paths` + `operationId`）
2. 为每个 `operationId` 创建 `PageEntry`，解析其 method、path 和 handler function

### 发现 2: 业务逻辑漏洞检测需语义提升

管理员自赋值、IDOR、明文密码等漏洞需要：
- 数据流分析：追踪 request 参数 → model 赋值
- 控制流对比：检查认证/授权检查的存在性
- 上下文理解：区分安全实现和不安全实现

当前纯正则匹配无法覆盖此类漏洞。

### 发现 3: 隐蔽的密钥命名

`SECRET_KEY = 'random'` 使用了异常简短的弱密钥值。`hardcoded_password` 检测的启发式需要更灵活的值形判断（如检测是否为常见弱密钥）。

---

## 四、下一步

1. **修复 OpenAPI 路由提取** — 解锁 Connexion/FastAPI-OpenAPI 类项目
2. **弱密钥检测增强** — 检测 `SECRET_KEY`、`JWT_SECRET` 等已知敏感变量名的弱值
3. **复测 VAmPI** — 修复后重新审计，期望路由覆盖率 > 80%
4. **部署第二个靶场** — Juice Shop (Node/TypeScript) 或 crAPI 验证 JS/TS 支持

---

*文档版本：v1.0 | 日期：2026-07-29*
