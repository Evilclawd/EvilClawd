"""Configuration management for the scanner application.

Loads configuration from environment variables and .env files using
Pydantic's settings management. Provides sensible defaults for all
settings while allowing override via environment.

Provides:
- Config: Pydantic model with all application settings
- load_config: Factory function to create Config instance
"""

import os

from pydantic import BaseModel, Field


class Config(BaseModel):
    """Application configuration loaded from environment and config file.

    All settings have sensible defaults. Override via environment variables
    or .env file. See .env.example for documentation of available settings.

    Attributes:
        anthropic_api_key: API key for Anthropic Claude (from ANTHROPIC_API_KEY env)
        database_url: SQLAlchemy database URL (default: SQLite in current dir)
        llm_model: Default LLM model identifier
        context_threshold_tokens: Token count that triggers context compaction
        require_scope_authorization: Whether to enforce scope checks (SAFE-01)
        guided_mode: Whether to require approval for MODERATE/DESTRUCTIVE tools
    """

    # API Keys
    anthropic_api_key: str = Field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", "")
    )
    telegram_bot_token: str = Field(
        default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN", "")
    )

    # Database
    database_url: str = Field(default="sqlite+aiosqlite:///scanner.db")

    # LLM Settings
    llm_model: str = Field(default="claude-sonnet-4-5-20250929")
    context_threshold_tokens: int = Field(default=50000)

    # Safety Settings
    require_scope_authorization: bool = Field(default=True)
    guided_mode: bool = Field(default=True)  # User approval for MODERATE/DESTRUCTIVE


def load_config() -> Config:
    """Load configuration from environment and .env file.

    Creates a Config instance with values from environment variables,
    falling back to defaults for any unset values.

    Returns:
        Populated Config instance
    """
    return Config()
