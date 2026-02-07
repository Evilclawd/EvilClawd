"""Anthropic Claude provider implementation.

Implements the LLMProvider protocol using the Anthropic SDK for Claude API integration.
"""

import os
from typing import AsyncIterator

from anthropic import AsyncAnthropic


class AnthropicProvider:
    """Anthropic Claude provider implementation.

    Provides async access to Claude models via the Anthropic API, with support
    for tool calling, streaming responses, and token counting.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-5-20250929",
    ):
        """Initialize the Anthropic provider.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            model: Default model to use for completions
        """
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable not set and no api_key provided"
            )
        self.default_model = model
        self.client = AsyncAnthropic(api_key=self.api_key)

    async def complete(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        model: str | None = None,
    ) -> dict:
        """Send a completion request to Claude.

        Args:
            messages: List of message dicts with 'role' and 'content' keys
            tools: Optional list of tool definitions in Anthropic schema format
            model: Optional model override (uses default if None)

        Returns:
            Response dict with 'content', 'stop_reason', 'usage', etc.
        """
        model_to_use = model or self.default_model

        # Build request parameters
        params = {
            "model": model_to_use,
            "messages": messages,
            "max_tokens": 4096,
        }

        if tools:
            params["tools"] = tools

        # Send request
        response = await self.client.messages.create(**params)

        # Convert response to dict format
        return {
            "id": response.id,
            "content": [
                {
                    "type": block.type,
                    "text": getattr(block, "text", None),
                    "id": getattr(block, "id", None),
                    "name": getattr(block, "name", None),
                    "input": getattr(block, "input", None),
                }
                for block in response.content
            ],
            "model": response.model,
            "role": response.role,
            "stop_reason": response.stop_reason,
            "stop_sequence": response.stop_sequence,
            "usage": {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
        }

    async def stream(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        model: str | None = None,
    ) -> AsyncIterator[dict]:
        """Stream a completion request from Claude.

        Args:
            messages: List of message dicts with 'role' and 'content' keys
            tools: Optional list of tool definitions in Anthropic schema format
            model: Optional model override (uses default if None)

        Yields:
            Response chunks as they arrive from Claude
        """
        model_to_use = model or self.default_model

        # Build request parameters
        params = {
            "model": model_to_use,
            "messages": messages,
            "max_tokens": 4096,
        }

        if tools:
            params["tools"] = tools

        # Stream response
        async with self.client.messages.stream(**params) as stream:
            async for event in stream:
                # Convert event to dict format
                yield {
                    "type": event.type,
                    "data": event.data if hasattr(event, "data") else None,
                }

    async def count_tokens(self, messages: list[dict]) -> int:
        """Count tokens in a message list using Claude's token counting.

        Args:
            messages: List of message dicts to count tokens for

        Returns:
            Approximate token count
        """
        # Use Anthropic's token counting API
        response = await self.client.messages.count_tokens(
            model=self.default_model,
            messages=messages,
        )
        return response.input_tokens
