"""
插件加载器

从文件或目录加载插件
"""

import importlib.util
import logging
from pathlib import Path
from typing import List

from .base import BasePlugin, PluginRegistry, plugin_registry

logger = logging.getLogger(__name__)


class PluginLoader:
    """插件加载器"""

    def __init__(self, registry: PluginRegistry = None):
        self.registry = registry or plugin_registry

    def load_from_file(self, file_path: str) -> BasePlugin:
        """
        从文件加载插件

        Args:
            file_path: 插件文件路径

        Returns:
            加载的插件实例
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Plugin file not found: {file_path}")

        if not path.suffix == '.py':
            raise ValueError(f"Plugin file must be a Python file: {file_path}")

        # 动态加载模块
        module_name = path.stem
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Failed to load plugin module: {file_path}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # 查找插件类
        plugin_class = None
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr is not BasePlugin:
                if hasattr(attr, 'metadata'):
                    plugin_class = attr
                    break

        if plugin_class is None:
            raise ValueError(f"No plugin class found in {file_path}")

        # 创建插件实例
        plugin = plugin_class(plugin_class.metadata)
        self.registry.register(plugin)
        logger.info(f"Loaded plugin: {plugin.metadata.name} from {file_path}")

        return plugin

    def load_from_directory(self, directory: str) -> list[BasePlugin]:
        """
        从目录加载所有插件

        Args:
            directory: 插件目录路径

        Returns:
            加载的插件列表
        """
        path = Path(directory)
        if not path.exists():
            raise FileNotFoundError(f"Plugin directory not found: {directory}")

        if not path.is_dir():
            raise ValueError(f"Path is not a directory: {directory}")

        plugins = []
        for file_path in path.glob('*.py'):
            if file_path.name.startswith('_'):
                continue

            try:
                plugin = self.load_from_file(str(file_path))
                plugins.append(plugin)
            except Exception as e:
                logger.error(f"Failed to load plugin from {file_path}: {e}")

        logger.info(f"Loaded {len(plugins)} plugins from {directory}")
        return plugins

    def unload_plugin(self, name: str) -> None:
        """
        卸载插件

        Args:
            name: 插件名称
        """
        self.registry.unregister(name)
        logger.info(f"Unloaded plugin: {name}")


# 全局插件加载器
plugin_loader = PluginLoader()
