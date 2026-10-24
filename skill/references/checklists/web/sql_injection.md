# SQL 注入检查清单

## 概述

SQL 注入是一种常见的安全漏洞，攻击者可以通过在输入中注入恶意 SQL 代码来操纵数据库查询。

## 检查项

### 1. 字符串拼接 SQL 查询

**危险模式**:
```python
# Python - 危险
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)

# JavaScript - 危险
const query = `SELECT * FROM users WHERE username = '${username}'`;
db.query(query);

# Java - 危险
String query = "SELECT * FROM users WHERE username = '" + username + "'";
stmt.executeQuery(query);
```

**检查要点**:
- [ ] 检查所有 SQL 查询是否使用字符串拼接
- [ ] 检查用户输入是否直接拼接到查询中
- [ ] 检查是否使用了参数化查询或预编译语句

**安全模式**:
```python
# Python - 安全
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

# JavaScript - 安全
db.query("SELECT * FROM users WHERE username = ?", [username]);

# Java - 安全
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
stmt.setString(1, username);
```

### 2. ORM 查询中的原生 SQL

**危险模式**:
```python
# Django ORM - 危险
User.objects.raw("SELECT * FROM users WHERE username = '%s'" % username)

# SQLAlchemy - 危险
session.execute(text(f"SELECT * FROM users WHERE username = '{username}'"))
```

**检查要点**:
- [ ] 检查 ORM 中的原生 SQL 查询
- [ ] 检查是否使用了参数化绑定

### 3. LIKE 查询注入

**危险模式**:
```python
query = f"SELECT * FROM users WHERE name LIKE '%{search}%'"
```

**检查要点**:
- [ ] 检查 LIKE 查询中的用户输入
- [ ] 检查是否对特殊字符进行转义

### 4. ORDER BY 注入

**危险模式**:
```python
query = f"SELECT * FROM users ORDER BY {sort_column}"
```

**检查要点**:
- [ ] 检查 ORDER BY 子句中的用户输入
- [ ] 检查是否使用白名单验证排序字段

### 5. 动态表名/列名

**危险模式**:
```python
query = f"SELECT * FROM {table_name}"
```

**检查要点**:
- [ ] 检查动态表名/列名是否来自用户输入
- [ ] 检查是否使用白名单验证

### 6. 存储过程调用

**危险模式**:
```python
cursor.execute(f"CALL get_user('{username}')")
```

**检查要点**:
- [ ] 检查存储过程调用中的参数绑定
- [ ] 检查是否使用安全的调用方式

## 常见框架检查点

### Django

```python
# 危险
User.objects.raw("SELECT * FROM users WHERE id = %s" % user_id)
User.objects.extra(where=["username = '%s'" % username])

# 安全
User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])
User.objects.filter(username=username)
```

### Flask-SQLAlchemy

```python
# 危险
db.session.execute(f"SELECT * FROM users WHERE id = {user_id}")

# 安全
db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
```

### Express.js (node-mysql)

```javascript
// 危险
connection.query(`SELECT * FROM users WHERE id = ${userId}`);

// 安全
connection.query("SELECT * FROM users WHERE id = ?", [userId]);
```

## 验证方法

### 静态分析

1. 搜索 SQL 查询关键字：`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `EXECUTE`
2. 检查字符串拼接操作符：`+`, `.`, `%`, `f"..."`
3. 检查 ORM 原生查询方法：`raw()`, `execute()`, `extra()`

### 动态测试

1. 输入特殊字符：`'`, `"`, `;`, `--`, `/*`
2. 尝试 SQL 注入 payload：
   - `' OR '1'='1`
   - `'; DROP TABLE users; --`
   - `' UNION SELECT NULL--`

## 修复建议

1. **使用参数化查询**：所有 SQL 查询都使用参数化绑定
2. **使用 ORM**：优先使用 ORM 而不是原生 SQL
3. **输入验证**：对用户输入进行严格的验证和转义
4. **最小权限**：数据库账号使用最小权限原则
5. **WAF**：部署 Web 应用防火墙作为额外防线

## 参考资源

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
