"""
插件系统基础架构

提供插件的基类和注册机制，支持：
- 自定义漏洞检测规则
- 自定义报告格式
- 自定义验证方式
- 自定义修复策略
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Type


class PluginType(Enum):
    """插件类型"""
    DETECTION_RULE = "detection_rule"  # 漏洞检测规则
    REPORT_FORMAT = "report_format"    # 报告格式
    VERIFICATION = "verification"      # 验证方式
    REMEDIATION = "remediation"        # 修复策略


@dataclass
class PluginMetadata:
    """插件元数据"""
    name: str
    version: str
    author: str
    description: str
    plugin_type: PluginType
    supported_vuln_types: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    config_schema: Dict[str, Any] = field(default_factory=dict)


class BasePlugin(ABC):
    """插件基类"""

    def __init__(self, metadata: PluginMetadata, config: Optional[Dict[str, Any]] = None):
        self.metadata = metadata
        self.config = config or {}
        self._initialized = False

    @abstractmethod
    async def initialize(self) -> None:
        """初始化插件"""
        pass

    @abstractmethod
    async def execute(self, **kwargs) -> Any:
        """执行插件功能"""
        pass

    async def cleanup(self) -> None:
        """清理资源"""
        self._initialized = False

    def is_initialized(self) -> bool:
        """检查是否已初始化"""
        return self._initialized

    def get_config(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        return self.config.get(key, default)


class DetectionRulePlugin(BasePlugin):
    """漏洞检测规则插件"""

    @abstractmethod
    async def detect(self, code: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        检测漏洞

        Args:
            code: 代码内容
            context: 上下文信息（文件路径、语言等）

        Returns:
            发现的漏洞列表
        """
        pass


class ReportFormatPlugin(BasePlugin):
    """报告格式插件"""

    @abstractmethod
    async def format(self, findings: List[Dict[str, Any]], metadata: Dict[str, Any]) -> str:
        """
        格式化报告

        Args:
            findings: 漏洞列表
            metadata: 元数据

        Returns:
            格式化后的报告
        """
        pass


class VerificationPlugin(BasePlugin):
    """验证方式插件"""

    @abstractmethod
    async def verify(self, finding: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证漏洞

        Args:
            finding: 漏洞信息
            context: 上下文信息

        Returns:
            验证结果
        """
        pass


class RemediationPlugin(BasePlugin):
    """修复策略插件"""

    @abstractmethod
    async def generate_remediation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        生成修复建议

        Args:
            finding: 漏洞信息

        Returns:
            修复建议
        """
        pass


class PluginRegistry:
    """插件注册表"""

    def __init__(self):
        self._plugins: Dict[str, BasePlugin] = {}
        self._plugins_by_type: Dict[PluginType, List[str]] = {
            PluginType.DETECTION_RULE: [],
            PluginType.REPORT_FORMAT: [],
            PluginType.VERIFICATION: [],
            PluginType.REMEDIATION: [],
        }

    def register(self, plugin: BasePlugin) -> None:
        """注册插件"""
        name = plugin.metadata.name
        if name in self._plugins:
            raise ValueError(f"Plugin '{name}' already registered")

        self._plugins[name] = plugin
        self._plugins_by_type[plugin.metadata.plugin_type].append(name)

    def unregister(self, name: str) -> None:
        """注销插件"""
        if name not in self._plugins:
            raise ValueError(f"Plugin '{name}' not found")

        plugin = self._plugins[name]
        del self._plugins[name]
        self._plugins_by_type[plugin.metadata.plugin_type].remove(name)

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """获取插件"""
        return self._plugins.get(name)

    def get_plugins_by_type(self, plugin_type: PluginType) -> List[BasePlugin]:
        """按类型获取插件列表"""
        return [self._plugins[name] for name in self._plugins_by_type[plugin_type]]

    def list_plugins(self) -> List[str]:
        """列出所有插件"""
        return list(self._plugins.keys())

    async def initialize_all(self) -> None:
        """初始化所有插件"""
        for plugin in self._plugins.values():
            if not plugin.is_initialized():
                await plugin.initialize()

    async def cleanup_all(self) -> None:
        """清理所有插件"""
        for plugin in self._plugins.values():
            await plugin.cleanup()


# 全局插件注册表
plugin_registry = PluginRegistry()


def register_plugin(plugin_class: Type[BasePlugin], config: Optional[Dict[str, Any]] = None) -> BasePlugin:
    """注册插件的装饰器"""
    def decorator(cls):
        # 创建插件实例
        metadata = getattr(cls, 'metadata', None)
        if metadata is None:
            raise ValueError(f"Plugin class {cls.__name__} must have 'metadata' attribute")

        instance = cls(metadata, config)
        plugin_registry.register(instance)
        return cls

    return decorator
