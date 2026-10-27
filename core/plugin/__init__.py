"""插件系统"""

from .base import (
    BasePlugin,
    DetectionRulePlugin,
    PluginMetadata,
    PluginRegistry,
    PluginType,
    RemediationPlugin,
    ReportFormatPlugin,
    VerificationPlugin,
    plugin_registry,
    register_plugin,
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
