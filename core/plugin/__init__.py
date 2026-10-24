"""插件系统"""

from .base import (
    BasePlugin,
    PluginMetadata,
    PluginType,
    PluginRegistry,
    plugin_registry,
    register_plugin,
    DetectionRulePlugin,
    ReportFormatPlugin,
    VerificationPlugin,
    RemediationPlugin,
)
from .loader import PluginLoader, plugin_loader

__all__ = [
    'BasePlugin',
    'PluginMetadata',
    'PluginType',
    'PluginRegistry',
    'plugin_registry',
    'register_plugin',
    'DetectionRulePlugin',
    'ReportFormatPlugin',
    'VerificationPlugin',
    'RemediationPlugin',
    'PluginLoader',
    'plugin_loader',
]
