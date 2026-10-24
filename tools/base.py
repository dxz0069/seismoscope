"""
Vibe Sec Platform — 工具基类

定义 AgentTool 基类和工具注册表。
所有工具都需要继承 AgentTool 并实现必要的方法。
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import logging


logger = logging.getLogger(__name__)


@dataclass
class ToolParameter:
    """工具参数定义"""
    name: str
    type: str  # "string", "integer", "number", "boolean", "array", "object"
    description: str
    required: bool = True
    default: Any = None
    enum: Optional[List[Any]] = None


@dataclass
class ToolDefinition:
    """工具定义"""
    name: str
    description: str
    parameters: List[ToolParameter] = field(default_factory=list)
    returns: Optional[str] = None
    examples: List[Dict[str, Any]] = field(default_factory=list)

    def to_openai_format(self) -> Dict[str, Any]:
        """转换为 OpenAI function calling 格式"""
        properties = {}
        required = []

        for param in self.parameters:
            prop = {
                "type": param.type,
                "description": param.description,
            }
            if param.enum:
                prop["enum"] = param.enum
            if param.default is not None:
                prop["default"] = param.default

            properties[param.name] = prop

            if param.required:
                required.append(param.name)

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }


class AgentTool(ABC):
    """
    智能体工具基类

    所有工具都需要继承此类并实现必要的方法。

    Example:
        class ReadFileTool(AgentTool):
            def __init__(self):
                super().__init__(
                    definition=ToolDefinition(
                        name="read_file",
                        description="读取文件内容",
                        parameters=[
                            ToolParameter(
                                name="file_path",
                                type="string",
                                description="文件路径",
                            )
                        ],
                    )
                )

            async def execute(self, file_path: str) -> Dict[str, Any]:
                with open(file_path, 'r') as f:
                    content = f.read()
                return {"content": content}
    """

    def __init__(self, definition: ToolDefinition):
        self.definition = definition

    @property
    def name(self) -> str:
        """工具名称"""
        return self.definition.name

    @property
    def description(self) -> str:
        """工具描述"""
        return self.definition.description

    @abstractmethod
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """
        执行工具

        Args:
            **kwargs: 工具参数

        Returns:
            工具执行结果
        """
        ...

    async def validate_parameters(self, **kwargs) -> bool:
        """
        验证参数

        Args:
            **kwargs: 工具参数

        Returns:
            参数是否有效
        """
        for param in self.definition.parameters:
            if param.required and param.name not in kwargs:
                logger.error(f"Missing required parameter: {param.name}")
                return False

            if param.name in kwargs and param.enum:
                if kwargs[param.name] not in param.enum:
                    logger.error(
                        f"Parameter {param.name} must be one of {param.enum}"
                    )
                    return False

        return True

    async def safe_execute(self, **kwargs) -> Dict[str, Any]:
        """
        安全执行工具（包含参数验证）

        Args:
            **kwargs: 工具参数

        Returns:
            工具执行结果或错误信息
        """
        # 验证参数
        if not await self.validate_parameters(**kwargs):
            return {
                "success": False,
                "error": "Invalid parameters",
            }

        try:
            result = await self.execute(**kwargs)
            return {
                "success": True,
                "result": result,
            }
        except Exception as e:
            logger.error(f"Tool execution failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
            }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name}>"


class ToolRegistry:
    """
    工具注册表

    管理所有工具的注册、发现和调用。

    Example:
        registry = ToolRegistry()
        registry.register(ReadFileTool())
        registry.register(WriteFileTool())

        # 获取工具
        tool = registry.get_tool("read_file")

        # 执行工具
        result = await registry.execute("read_file", file_path="test.py")
    """

    def __init__(self):
        self._tools: Dict[str, AgentTool] = {}

    def register(self, tool: AgentTool) -> None:
        """
        注册工具

        Args:
            tool: 工具实例
        """
        if tool.name in self._tools:
            logger.warning(f"Tool {tool.name} already registered, overwriting")

        self._tools[tool.name] = tool
        logger.info(f"Registered tool: {tool.name}")

    def unregister(self, tool_name: str) -> None:
        """
        取消注册工具

        Args:
            tool_name: 工具名称
        """
        if tool_name in self._tools:
            del self._tools[tool_name]
            logger.info(f"Unregistered tool: {tool_name}")

    def get_tool(self, name: str) -> Optional[AgentTool]:
        """
        获取工具

        Args:
            name: 工具名称

        Returns:
            工具实例或 None
        """
        return self._tools.get(name)

    def list_tools(self) -> List[str]:
        """
        列出所有工具名称

        Returns:
            工具名称列表
        """
        return list(self._tools.keys())

    def get_tool_definitions(self) -> List[ToolDefinition]:
        """
        获取所有工具定义

        Returns:
            工具定义列表
        """
        return [tool.definition for tool in self._tools.values()]

    def get_openai_tool_definitions(self) -> List[Dict[str, Any]]:
        """
        获取 OpenAI 格式的工具定义

        Returns:
            OpenAI 格式的工具定义列表
        """
        return [
            tool.definition.to_openai_format()
            for tool in self._tools.values()
        ]

    async def execute(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """
        执行工具

        Args:
            tool_name: 工具名称
            **kwargs: 工具参数

        Returns:
            工具执行结果
        """
        tool = self.get_tool(tool_name)
        if not tool:
            return {
                "success": False,
                "error": f"Tool not found: {tool_name}",
            }

        return await tool.safe_execute(**kwargs)

    def __contains__(self, tool_name: str) -> bool:
        """检查工具是否已注册"""
        return tool_name in self._tools

    def __len__(self) -> int:
        """返回已注册的工具数量"""
        return len(self._tools)


# ========== 常用工具实现 ==========

class ReadFileTool(AgentTool):
    """读取文件内容工具"""

    def __init__(self):
        super().__init__(
            definition=ToolDefinition(
                name="read_file",
                description="读取文件内容",
                parameters=[
                    ToolParameter(
                        name="file_path",
                        type="string",
                        description="文件路径",
                    ),
                    ToolParameter(
                        name="encoding",
                        type="string",
                        description="文件编码",
                        required=False,
                        default="utf-8",
                    ),
                ],
                returns="文件内容",
            )
        )

    async def execute(self, file_path: str, encoding: str = "utf-8") -> Dict[str, Any]:
        """执行读取文件"""
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                content = f.read()

            return {
                "file_path": file_path,
                "content": content,
                "size": len(content),
            }
        except Exception as e:
            raise Exception(f"Failed to read file: {e}") from e


class WriteFileTool(AgentTool):
    """写入文件工具"""

    def __init__(self):
        super().__init__(
            definition=ToolDefinition(
                name="write_file",
                description="写入文件内容",
                parameters=[
                    ToolParameter(
                        name="file_path",
                        type="string",
                        description="文件路径",
                    ),
                    ToolParameter(
                        name="content",
                        type="string",
                        description="文件内容",
                    ),
                    ToolParameter(
                        name="encoding",
                        type="string",
                        description="文件编码",
                        required=False,
                        default="utf-8",
                    ),
                ],
                returns="写入结果",
            )
        )

    async def execute(self, file_path: str, content: str, encoding: str = "utf-8") -> Dict[str, Any]:
        """执行写入文件"""
        try:
            with open(file_path, 'w', encoding=encoding) as f:
                f.write(content)

            return {
                "file_path": file_path,
                "size": len(content),
                "success": True,
            }
        except Exception as e:
            raise Exception(f"Failed to write file: {e}") from e


class ListDirectoryTool(AgentTool):
    """列出目录内容工具"""

    def __init__(self):
        super().__init__(
            definition=ToolDefinition(
                name="list_directory",
                description="列出目录内容",
                parameters=[
                    ToolParameter(
                        name="directory_path",
                        type="string",
                        description="目录路径",
                    ),
                    ToolParameter(
                        name="recursive",
                        type="boolean",
                        description="是否递归列出",
                        required=False,
                        default=False,
                    ),
                ],
                returns="目录内容列表",
            )
        )

    async def execute(self, directory_path: str, recursive: bool = False) -> Dict[str, Any]:
        """执行列出目录"""
        import os

        try:
            items = []

            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    for file in files:
                        items.append(os.path.join(root, file))
                    for dir_name in dirs:
                        items.append(os.path.join(root, dir_name))
            else:
                for item in os.listdir(directory_path):
                    items.append(item)

            return {
                "directory_path": directory_path,
                "items": items,
                "count": len(items),
            }
        except Exception as e:
            raise Exception(f"Failed to list directory: {e}") from e
