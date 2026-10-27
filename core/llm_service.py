"""
Vibe Sec Platform — LLM 服务基类

定义 LLM 服务的接口和基类实现。
支持多种 LLM 提供商（OpenAI、Anthropic 等）。
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


LLM_REQUEST_TIMEOUT_SECONDS = 45.0
DEEPSEEK_API_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_DEFAULT_MODEL = "deepseek-v4-flash"


def normalize_llm_api_key(api_key: str) -> str:
    """Validate a provider credential before it can reach an HTTP client.

    Provider tokens are transmitted in HTTP headers, which only accept a
    printable ASCII token.  Reject labels, quotes, whitespace, and copied
    non-ASCII prose at the configuration boundary rather than allowing a task
    to fail later with a low-level header encoding error.
    """
    normalized = str(api_key or "").strip()
    if not normalized:
        raise ValueError("LLM configuration requires an API key")
    if any(ord(char) < 33 or ord(char) > 126 for char in normalized):
        raise ValueError(
            "LLM API key must be a single printable ASCII token; "
            "remove provider labels, quotes, and spaces"
        )
    return normalized


async def _await_llm_request(request, provider: str):
    """Bound the whole client operation, including a stalled response body."""
    try:
        return await asyncio.wait_for(request, timeout=LLM_REQUEST_TIMEOUT_SECONDS)
    except TimeoutError as exc:
        raise TimeoutError(
            f"{provider} LLM request timed out after {LLM_REQUEST_TIMEOUT_SECONDS:g} seconds"
        ) from exc


@dataclass
class LLMMessage:
    """LLM 消息"""
    role: str  # "system", "user", "assistant", "tool"
    content: str
    name: str | None = None
    tool_calls: list[dict[str, Any]] | None = None
    tool_call_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """转换为字典"""
        msg = {"role": self.role, "content": self.content}
        if self.name:
            msg["name"] = self.name
        if self.tool_calls:
            msg["tool_calls"] = self.tool_calls
        if self.tool_call_id:
            msg["tool_call_id"] = self.tool_call_id
        return msg


@dataclass
class LLMResponse:
    """LLM 响应"""
    content: str
    tool_calls: list[dict[str, Any]] | None = None
    usage: dict[str, int] = field(default_factory=dict)
    finish_reason: str | None = None

    @property
    def has_tool_calls(self) -> bool:
        """是否有工具调用"""
        return bool(self.tool_calls)


class LLMService(ABC):
    """
    LLM 服务抽象基类

    提供统一的接口，支持多种 LLM 提供商。

    Example:
        class OpenAIService(LLMService):
            def __init__(self, api_key: str):
                super().__init__(provider="openai", model="gpt-4")
                self.client = OpenAI(api_key=api_key)

            async def chat(self, messages, **kwargs) -> LLMResponse:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[m.to_dict() for m in messages],
                    **kwargs
                )
                return LLMResponse(
                    content=response.choices[0].message.content,
                    tool_calls=response.choices[0].message.tool_calls,
                    usage=response.usage.model_dump(),
                )
    """

    def __init__(self, provider: str, model: str = "gpt-4"):
        self.provider = provider
        self.model = model

    @abstractmethod
    async def chat(
        self,
        messages: list[LLMMessage],
        *,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        tools: list[dict[str, Any]] | None = None,
        **kwargs
    ) -> LLMResponse:
        """
        发送聊天请求

        Args:
            messages: 消息列表
            model: 模型标识（覆盖默认模型）
            temperature: 温度参数
            max_tokens: 最大 token 数
            tools: 工具定义列表
            **kwargs: 其他参数

        Returns:
            LLMResponse 响应
        """
        ...

    async def chat_with_retries(
        self,
        messages: list[LLMMessage],
        *,
        max_retries: int = 3,
        **kwargs
    ) -> LLMResponse:
        """
        带重试的聊天请求

        Args:
            messages: 消息列表
            max_retries: 最大重试次数
            **kwargs: 其他参数

        Returns:
            LLMResponse 响应
        """
        last_error = None

        for attempt in range(max_retries):
            try:
                return await self.chat(messages, **kwargs)
            except Exception as e:
                last_error = e
                logger.warning(
                    f"LLM call failed (attempt {attempt + 1}/{max_retries}): {e}"
                )
                if attempt < max_retries - 1:
                    import asyncio
                    await asyncio.sleep(2 ** attempt)  # 指数退避

        raise last_error

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} provider={self.provider} model={self.model}>"


class OpenAIService(LLMService):
    """
    OpenAI LLM 服务

    Example:
        service = OpenAIService(api_key="your-api-key")
        response = await service.chat([
            LLMMessage(role="user", content="Hello")
        ])
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4",
        base_url: str | None = None,
    ):
        super().__init__(provider="openai", model=model)
        self.api_key = normalize_llm_api_key(api_key)
        self.base_url = base_url

        # 延迟导入，避免启动时就需要安装 openai
        try:
            from openai import AsyncOpenAI
            options: dict[str, Any] = {
                "api_key": self.api_key,
                "timeout": LLM_REQUEST_TIMEOUT_SECONDS,
                "max_retries": 1,
            }
            if base_url:
                options["base_url"] = base_url
            self.client = AsyncOpenAI(**options)
        except ImportError:
            logger.error("openai package not installed; OpenAI provider is unavailable")
            self.client = None

    async def chat(
        self,
        messages: list[LLMMessage],
        *,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        tools: list[dict[str, Any]] | None = None,
        **kwargs
    ) -> LLMResponse:
        """发送 OpenAI 聊天请求"""
        if not self.client:
            raise RuntimeError("OpenAI client not initialized")

        # 转换消息格式
        openai_messages = [msg.to_dict() for msg in messages]

        # 构建请求参数
        params = {
            "model": model or self.model,
            "messages": openai_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            params["tools"] = tools
        for option in ("tool_choice", "parallel_tool_calls"):
            if option in kwargs:
                params[option] = kwargs[option]

        # 发送请求
        response = await _await_llm_request(
            self.client.chat.completions.create(**params),
            "OpenAI-compatible",
        )

        # 解析响应
        choice = response.choices[0]
        message = choice.message

        # 处理工具调用
        tool_calls = None
        if message.tool_calls:
            tool_calls = [
                {
                    "id": tc.id,
                    "type": tc.type,
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in message.tool_calls
            ]

        return LLMResponse(
            content=message.content or "",
            tool_calls=tool_calls,
            usage={
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            },
            finish_reason=choice.finish_reason,
        )


class AnthropicService(LLMService):
    """
    Anthropic Claude LLM 服务

    Example:
        service = AnthropicService(api_key="your-api-key")
        response = await service.chat([
            LLMMessage(role="user", content="Hello")
        ])
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-3-opus-20240229",
        base_url: str | None = None,
    ):
        super().__init__(provider="anthropic", model=model)
        self.api_key = normalize_llm_api_key(api_key)
        self.base_url = base_url

        # 延迟导入，避免启动时就需要安装 anthropic
        try:
            from anthropic import AsyncAnthropic
            options: dict[str, Any] = {"api_key": self.api_key}
            if base_url:
                options["base_url"] = base_url
            self.client = AsyncAnthropic(**options)
        except ImportError:
            logger.error("anthropic package not installed; Anthropic provider is unavailable")
            self.client = None

    async def chat(
        self,
        messages: list[LLMMessage],
        *,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        tools: list[dict[str, Any]] | None = None,
        **kwargs
    ) -> LLMResponse:
        """发送 Anthropic 聊天请求"""
        if not self.client:
            raise RuntimeError("Anthropic client not initialized")

        # 分离系统消息
        system_message = None
        user_messages = []

        for msg in messages:
            if msg.role == "system":
                system_message = msg.content
            else:
                user_messages.append(msg.to_dict())

        # 构建请求参数
        params = {
            "model": model or self.model,
            "messages": user_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        if system_message:
            params["system"] = system_message

        # 注意：Anthropic 的工具格式与 OpenAI 不同，需要转换
        # 这里简化处理，实际需要更复杂的转换逻辑

        # 发送请求
        response = await _await_llm_request(
            self.client.messages.create(**params),
            "Anthropic",
        )

        # 解析响应
        content = ""
        if response.content:
            for block in response.content:
                if block.type == "text":
                    content += block.text

        return LLMResponse(
            content=content,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
            finish_reason=response.stop_reason,
        )


class DeepSeekService(LLMService):
    """
    DeepSeek LLM 服务

    DeepSeek 使用 OpenAI 兼容接口

    Example:
        service = DeepSeekService(api_key="your-api-key")
        response = await service.chat([
            LLMMessage(role="user", content="Hello")
        ])
    """

    def __init__(self, api_key: str, model: str = DEEPSEEK_DEFAULT_MODEL):
        super().__init__(provider="deepseek", model=model)
        self.api_key = normalize_llm_api_key(api_key)

        # 延迟导入，避免启动时就需要安装 openai
        try:
            from openai import AsyncOpenAI
            self.client = AsyncOpenAI(
                api_key=self.api_key,
                base_url=DEEPSEEK_API_BASE_URL,
                timeout=LLM_REQUEST_TIMEOUT_SECONDS,
                max_retries=1,
            )
        except ImportError:
            logger.error("openai package not installed; DeepSeek provider is unavailable")
            self.client = None

    async def chat(
        self,
        messages: list[LLMMessage],
        *,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        tools: list[dict[str, Any]] | None = None,
        **kwargs
    ) -> LLMResponse:
        """发送 DeepSeek 聊天请求"""
        if not self.client:
            raise RuntimeError("DeepSeek client not initialized")

        # 转换消息格式
        openai_messages = [msg.to_dict() for msg in messages]

        # 构建请求参数
        params = {
            "model": model or self.model,
            "messages": openai_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            params["tools"] = tools
        for option in ("tool_choice", "parallel_tool_calls"):
            if option in kwargs:
                params[option] = kwargs[option]

        # 发送请求
        response = await _await_llm_request(
            self.client.chat.completions.create(**params),
            "DeepSeek",
        )

        # 解析响应
        choice = response.choices[0]
        message = choice.message

        # 处理工具调用
        tool_calls = None
        if message.tool_calls:
            tool_calls = [
                {
                    "id": tc.id,
                    "type": tc.type,
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in message.tool_calls
            ]

        return LLMResponse(
            content=message.content or "",
            tool_calls=tool_calls,
            usage={
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            },
            finish_reason=choice.finish_reason,
        )


class ConfiguredLLMService(LLMService):
    """Apply an audit model configuration without changing provider implementations."""

    def __init__(
        self,
        service: LLMService,
        *,
        provider: str,
        model: str,
        temperature: float,
        max_tokens: int,
    ):
        super().__init__(provider=provider, model=model)
        self._service = service
        self.temperature = temperature
        self.max_tokens = max_tokens

    async def chat(
        self,
        messages: list[LLMMessage],
        *,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        **kwargs,
    ) -> LLMResponse:
        return await self._service.chat(
            messages,
            model=model or self.model,
            temperature=self.temperature if temperature is None else temperature,
            max_tokens=self.max_tokens if max_tokens is None else max_tokens,
            tools=tools,
            **kwargs,
        )


def create_configured_llm_service(
    *,
    provider: str,
    api_key: str,
    model_name: str,
    api_base: str | None = None,
    temperature: float = 0.2,
    max_tokens: int = 4096,
) -> LLMService:
    """Build a provider client from a persisted local model configuration.

    OpenAI-compatible providers include DeepSeek and self-hosted endpoints.  The
    caller owns credential storage; this factory never logs or serializes keys.
    """
    normalized_provider = str(provider or "").strip().lower()
    normalized_base = str(api_base or "").strip() or None
    normalized_model = str(model_name or "").strip()
    normalized_key = normalize_llm_api_key(api_key)
    if not normalized_model:
        raise ValueError("LLM configuration requires an API key and model name")

    if normalized_provider == "anthropic":
        service: LLMService = AnthropicService(
            api_key=normalized_key,
            model=normalized_model,
            base_url=normalized_base,
        )
    elif normalized_provider == "openai":
        service = OpenAIService(
            api_key=normalized_key,
            model=normalized_model,
            base_url=normalized_base,
        )
    elif normalized_provider in {"openai_compatible", "auto"}:
        if not normalized_base:
            raise ValueError("OpenAI-compatible LLM configuration requires an API Base URL")
        service = OpenAIService(
            api_key=api_key,
            model=normalized_model,
            base_url=normalized_base,
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")

    if getattr(service, "client", None) is None:
        raise RuntimeError(f"{normalized_provider} LLM support is unavailable in this environment")
    return ConfiguredLLMService(
        service,
        provider=normalized_provider,
        model=normalized_model,
        temperature=float(temperature),
        max_tokens=int(max_tokens),
    )


class MockLLMService(LLMService):
    """
    模拟 LLM 服务（用于测试）

    Example:
        service = MockLLMService(responses=[
            LLMResponse(content="Hello!"),
        ])
    """

    def __init__(self, responses: list[LLMResponse] | None = None):
        super().__init__(provider="mock", model="mock-model")
        self.responses = responses or []
        self.call_count = 0

    async def chat(
        self,
        messages: list[LLMMessage],
        *,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        tools: list[dict[str, Any]] | None = None,
        **kwargs
    ) -> LLMResponse:
        """返回预设的响应"""
        if self.call_count < len(self.responses):
            response = self.responses[self.call_count]
            self.call_count += 1
            return response

        # 默认响应
        return LLMResponse(
            content="This is a mock response.",
            usage={"prompt_tokens": 10, "completion_tokens": 20},
        )
