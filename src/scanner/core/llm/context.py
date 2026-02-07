"""Context window management with automatic summarization.

Manages LLM context to prevent token overflow by tracking usage and
summarizing older messages when approaching token limits.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .client import LLMClient


class ContextManager:
    """Manages LLM context window to prevent token overflow.

    Tracks message history and token usage, automatically compacting
    older messages into summaries when approaching token limits.
    """

    def __init__(
        self,
        client: "LLMClient",
        threshold_tokens: int = 50000,
    ):
        """Initialize the context manager.

        Args:
            client: LLM client for token counting and summarization
            threshold_tokens: Token count that triggers context compaction
        """
        self.client = client
        self.threshold_tokens = threshold_tokens
        self.messages: list[dict] = []
        self._current_tokens = 0

    async def add_message(self, message: dict) -> None:
        """Add a message to the context.

        Args:
            message: Message dict with 'role' and 'content' keys
        """
        self.messages.append(message)
        # Recount tokens for the full message list
        self._current_tokens = await self.client.count_tokens(self.messages)

        # Check if we need to compact
        if self._current_tokens > self.threshold_tokens:
            await self.compact_context()

    async def count_tokens(self, messages: list[dict]) -> int:
        """Count tokens in a message list.

        Args:
            messages: List of message dicts

        Returns:
            Token count
        """
        return await self.client.count_tokens(messages)

    async def compact_context(self) -> None:
        """Compact context by summarizing older messages.

        Takes the oldest half of messages (excluding system message if present),
        summarizes them using the LLM, and replaces them with a summary message.
        """
        if len(self.messages) < 3:
            # Not enough messages to compact
            return

        # Separate system message if present
        system_msg = None
        messages_to_process = self.messages

        if self.messages[0].get("role") == "system":
            system_msg = self.messages[0]
            messages_to_process = self.messages[1:]

        # Split messages - summarize first half
        split_point = len(messages_to_process) // 2
        to_summarize = messages_to_process[:split_point]
        to_keep = messages_to_process[split_point:]

        # Create summarization prompt
        summary_messages = [
            {
                "role": "user",
                "content": f"""Summarize this conversation history concisely, preserving key facts and decisions:

{self._format_messages_for_summary(to_summarize)}

Provide a concise summary in 2-3 sentences.""",
            }
        ]

        # Get summary from LLM
        response = await self.client.complete(summary_messages)

        # Extract summary text
        summary_text = ""
        for block in response.get("content", []):
            if block.get("type") == "text":
                summary_text = block.get("text", "")
                break

        # Rebuild message list
        new_messages = []
        if system_msg:
            new_messages.append(system_msg)

        new_messages.append(
            {
                "role": "assistant",
                "content": f"[Context Summary] {summary_text}",
            }
        )
        new_messages.extend(to_keep)

        self.messages = new_messages
        self._current_tokens = await self.client.count_tokens(self.messages)

    def _format_messages_for_summary(self, messages: list[dict]) -> str:
        """Format messages for summarization prompt.

        Args:
            messages: List of message dicts

        Returns:
            Formatted string representation
        """
        formatted = []
        for msg in messages:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            formatted.append(f"{role.upper()}: {content}")
        return "\n\n".join(formatted)

    def get_messages(self) -> list[dict]:
        """Get current message list.

        Returns:
            List of message dicts
        """
        return self.messages.copy()

    def clear(self) -> None:
        """Clear all messages and reset token count."""
        self.messages = []
        self._current_tokens = 0

    @property
    def current_tokens(self) -> int:
        """Get current token count.

        Returns:
            Current token count
        """
        return self._current_tokens
