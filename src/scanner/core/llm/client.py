"""LLM provider abstraction layer.

Provides a protocol-based interface for LLM providers, enabling multi-provider
support and easy switching between different LLM backends.
"""

from typing import AsyncIterator, Protocol, runtime_checkable


@runtime_checkable
class LLMProvider(Protocol):
    """Protocol defining the interface for LLM providers.

    This allows for flexible provider implementations (Anthropic, OpenAI, local models, etc.)
    while maintaining a consistent interface for the rest of the application.
    """

    async def complete(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        model: str | None = None,
    ) -> dict:
        """Send a completion request to the LLM.

        Args:
            messages: List of message dicts with 'role' and 'content' keys
            tools: Optional list of tool definitions in Anthropic schema format
            model: Optional model override (uses provider default if None)

        Returns:
            Response dict with 'content', 'stop_reason', 'usage', etc.
        """
        ...

    async def stream(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        model: str | None = None,
    ) -> AsyncIterator[dict]:
        """Stream a completion request to the LLM.

        Args:
            messages: List of message dicts with 'role' and 'content' keys
            tools: Optional list of tool definitions in Anthropic schema format
            model: Optional model override (uses provider default if None)

        Yields:
            Response chunks as they arrive from the provider
        """
        ...

    async def count_tokens(self, messages: list[dict]) -> int:
        """Count tokens in a message list.

        Args:
            messages: List of message dicts to count tokens for

        Returns:
            Approximate token count
        """
        ...


class LLMClient:
    """Wrapper client that uses a provider for LLM operations.

    This class provides a clean interface for the application to interact with
    LLMs while delegating actual provider logic to injected provider instances.
    """

    def __init__(self, provider: LLMProvider):
        """Initialize the client with a provider.

        Args:
            provider: An instance implementing the LLMProvider protocol
        """
        self.provider = provider

    async def complete(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        model: str | None = None,
    ) -> dict:
        """Send a completion request via the provider.

        Args:
            messages: List of message dicts
            tools: Optional tool definitions
            model: Optional model override

        Returns:
            Provider response dict
        """
        return await self.provider.complete(messages, tools, model)

    async def stream(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        model: str | None = None,
    ) -> AsyncIterator[dict]:
        """Stream a completion request via the provider.

        Args:
            messages: List of message dicts
            tools: Optional tool definitions
            model: Optional model override

        Yields:
            Response chunks from the provider
        """
        async for chunk in self.provider.stream(messages, tools, model):
            yield chunk

    async def count_tokens(self, messages: list[dict]) -> int:
        """Count tokens via the provider.

        Args:
            messages: List of message dicts

        Returns:
            Token count
        """
        return await self.provider.count_tokens(messages)
