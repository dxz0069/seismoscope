# 插件开发指南

## 概述

Vibe Sec Platform 支持通过插件系统扩展功能。插件可以实现自定义的漏洞检测规则、报告格式、验证方式和修复策略。

## 插件类型

| 类型 | 说明 | 基类 |
|------|------|------|
| `detection_rule` | 漏洞检测规则 | `DetectionRulePlugin` |
| `report_format` | 报告格式 | `ReportFormatPlugin` |
| `verification` | 验证方式 | `VerificationPlugin` |
| `remediation` | 修复策略 | `RemediationPlugin` |

## 插件结构

每个插件是一个 Python 文件，包含：
1. 插件元数据（`metadata`）
2. 插件类（继承自相应的基类）
3. 实现抽象方法

## 创建检测规则插件

### 基本结构

```python
from core.plugin import (
    DetectionRulePlugin,
    PluginMetadata,
    PluginType,
)
from typing import Any, Dict, List


class MyCustomPlugin(DetectionRulePlugin):
    """自定义检测规则"""

    metadata = PluginMetadata(
        name="my_custom_plugin",
        version="1.0.0",
        author="Your Name",
        description="My custom detection rule",
        plugin_type=PluginType.DETECTION_RULE,
        supported_vuln_types=["custom_vuln"],
        dependencies=[],
        config_schema={
            "strict_mode": {
                "type": "boolean",
                "default": False,
                "description": "Enable strict mode"
            }
        }
    )

    async def initialize(self) -> None:
        """初始化插件"""
        self.strict_mode = self.get_config("strict_mode", False)
        self._initialized = True

    async def detect(self, code: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """检测漏洞"""
        findings = []
        
        # 实现检测逻辑
        import re
        pattern = r"your_pattern_here"
        matches = re.finditer(pattern, code)
        
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            findings.append({
                "vulnerability_type": "custom_vuln",
                "severity": "high",
                "confidence": 0.85,
                "title": "Custom Vulnerability",
                "description": "Description of the vulnerability",
                "line_start": line_num,
                "line_end": line_num,
                "evidence": [
                    {
                        "type": "code_snippet",
                        "content": match.group(),
                        "line": line_num,
                    }
                ],
                "plugin": self.metadata.name,
            })
        
        return findings

    async def cleanup(self) -> None:
        """清理资源"""
        pass
```

### 元数据说明

- `name`: 插件名称（唯一标识）
- `version`: 版本号
- `author`: 作者
- `description`: 描述
- `plugin_type`: 插件类型
- `supported_vuln_types`: 支持的漏洞类型列表
- `dependencies`: 依赖的其他插件
- `config_schema`: 配置项定义

### 配置项

通过 `config_schema` 定义配置项，用户可以在加载插件时传入配置：

```python
config_schema={
    "strict_mode": {
        "type": "boolean",
        "default": False,
        "description": "Enable strict mode"
    },
    "max_results": {
        "type": "integer",
        "default": 100,
        "description": "Maximum number of results"
    }
}
```

在 `initialize` 方法中读取配置：

```python
async def initialize(self) -> None:
    self.strict_mode = self.get_config("strict_mode", False)
    self.max_results = self.get_config("max_results", 100)
    self._initialized = True
```

## 创建报告格式插件

```python
from core.plugin import (
    ReportFormatPlugin,
    PluginMetadata,
    PluginType,
)


class MyReportFormat(ReportFormatPlugin):
    """自定义报告格式"""

    metadata = PluginMetadata(
        name="my_report_format",
        version="1.0.0",
        author="Your Name",
        description="My custom report format",
        plugin_type=PluginType.REPORT_FORMAT,
    )

    async def initialize(self) -> None:
        self._initialized = True

    async def format(self, findings: List[Dict[str, Any]], metadata: Dict[str, Any]) -> str:
        """格式化报告"""
        lines = ["# Security Audit Report", ""]
        
        # 添加摘要
        lines.append(f"Total findings: {len(findings)}")
        lines.append("")
        
        # 添加详细信息
        for i, finding in enumerate(findings, 1):
            lines.append(f"## {i}. {finding.get('title', 'Unknown')}")
            lines.append(f"- Severity: {finding.get('severity', 'medium')}")
            lines.append(f"- File: {finding.get('file_path', '')}:{finding.get('line_start', 0)}")
            lines.append("")
        
        return "\n".join(lines)

    async def cleanup(self) -> None:
        pass
```

## 创建验证方式插件

```python
from core.plugin import (
    VerificationPlugin,
    PluginMetadata,
    PluginType,
)


class MyVerification(VerificationPlugin):
    """自定义验证方式"""

    metadata = PluginMetadata(
        name="my_verification",
        version="1.0.0",
        author="Your Name",
        description="My custom verification method",
        plugin_type=PluginType.VERIFICATION,
    )

    async def initialize(self) -> None:
        self._initialized = True

    async def verify(self, finding: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """验证漏洞"""
        # 实现验证逻辑
        return {
            "verified": True,
            "confidence": 0.9,
            "explanation": "Verification explanation",
        }

    async def cleanup(self) -> None:
        pass
```

## 创建修复策略插件

```python
from core.plugin import (
    RemediationPlugin,
    PluginMetadata,
    PluginType,
)


class MyRemediation(RemediationPlugin):
    """自定义修复策略"""

    metadata = PluginMetadata(
        name="my_remediation",
        version="1.0.0",
        author="Your Name",
        description="My custom remediation strategy",
        plugin_type=PluginType.REMEDIATION,
    )

    async def initialize(self) -> None:
        self._initialized = True

    async def generate_remediation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """生成修复建议"""
        return {
            "ai_patch_prompt": "Fix instructions...",
            "patch_strategy": "custom_strategy",
            "patch_constraints": [],
            "retest_plan": [],
            "acceptance_criteria": ["Criterion 1", "Criterion 2"],
        }

    async def cleanup(self) -> None:
        pass
```

## 加载和使用插件

### 从文件加载

```python
from core.plugin import plugin_loader

# 加载单个插件
plugin = plugin_loader.load_from_file("path/to/my_plugin.py")

# 初始化插件
await plugin.initialize()
```

### 从目录加载

```python
from core.plugin import plugin_loader

# 加载目录中的所有插件
plugins = plugin_loader.load_from_directory("path/to/plugins/")

# 初始化所有插件
for plugin in plugins:
    await plugin.initialize()
```

### 使用插件进行检测

```python
from core.plugin import plugin_registry, PluginType

# 获取所有检测规则插件
detection_plugins = plugin_registry.get_plugins_by_type(PluginType.DETECTION_RULE)

# 使用插件检测漏洞
code = "your code here"
context = {"file_path": "app.py", "language": "python"}

all_findings = []
for plugin in detection_plugins:
    findings = await plugin.detect(code, context)
    all_findings.extend(findings)
```

## 插件最佳实践

### 1. 错误处理

始终捕获并处理异常：

```python
async def detect(self, code: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    try:
        # 检测逻辑
        pass
    except Exception as e:
        logger.error(f"Detection failed: {e}")
        return []
```

### 2. 性能优化

对于大量代码，考虑分批处理：

```python
async def detect(self, code: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    lines = code.split('\n')
    batch_size = 1000
    all_findings = []
    
    for i in range(0, len(lines), batch_size):
        batch = '\n'.join(lines[i:i+batch_size])
        findings = await self._detect_batch(batch, i)
        all_findings.extend(findings)
    
    return all_findings
```

### 3. 缓存

使用缓存避免重复计算：

```python
from core.cache import cached

@cached(ttl=3600)
async def detect(self, code: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    # 检测逻辑
    pass
```

### 4. 日志

使用标准日志记录：

```python
import logging

logger = logging.getLogger(__name__)

async def detect(self, code: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    logger.info(f"Starting detection on {context.get('file_path')}")
    # 检测逻辑
    logger.info(f"Found {len(findings)} vulnerabilities")
    return findings
```

## 示例插件

查看 `plugins/examples/` 目录中的示例插件：
- `custom_sql_injection.py` - 自定义 SQL 注入检测
- 更多示例正在添加中...

## 插件开发流程

1. **设计插件**: 确定插件类型、功能、配置项
2. **实现插件**: 创建插件文件，实现基类方法
3. **测试插件**: 编写测试用例，验证插件功能
4. **文档化**: 编写插件文档，说明使用方法和配置
5. **发布插件**: 将插件放入 `plugins/` 目录或发布到插件市场

## 插件市场（规划中）

未来版本将支持插件市场，用户可以：
- 发布自己的插件
- 下载和使用社区插件
- 评分和评论插件
- 自动更新插件
