"""Base tool protocol and shared infrastructure for tool wrappers.

Provides:
- Tool protocol for consistent tool interface
- ToolResult dataclass for structured tool output
- Helper functions for binary checking and subprocess execution
- Retry logic with exponential backoff for transient failures
"""

import asyncio
import shutil
import structlog
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

logger = structlog.get_logger()


class ToolStatus(str, Enum):
    """Tool execution status."""
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    NOT_INSTALLED = "not_installed"


@dataclass
class ToolResult:
    """Structured result from a tool execution."""
    status: ToolStatus
    data: dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    error: str = ""
    duration_seconds: float = 0.0


@runtime_checkable
class Tool(Protocol):
    """Protocol for tool wrappers."""
    name: str
    binary_name: str

    async def run(self, target: str, **kwargs) -> ToolResult:
        """Execute tool on target."""
        ...

    def is_available(self) -> bool:
        """Check if tool binary is available."""
        ...


def check_binary(binary_name: str) -> bool:
    """Check if binary exists on PATH.

    Args:
        binary_name: Name of binary to check (e.g., "nmap", "subfinder")

    Returns:
        True if binary is available, False otherwise
    """
    return shutil.which(binary_name) is not None


async def run_subprocess(
    cmd: list[str],
    timeout: int = 300
) -> tuple[str, str, int]:
    """Run command via subprocess with timeout.

    Uses asyncio.create_subprocess_exec (NEVER shell=True) for safe execution.
    Kills process on timeout and ensures cleanup.

    Args:
        cmd: Command and arguments as list (e.g., ["nmap", "-sV", "target.com"])
        timeout: Timeout in seconds (default: 300)

    Returns:
        Tuple of (stdout, stderr, returncode)

    Raises:
        asyncio.TimeoutError: If command exceeds timeout
    """
    log = logger.bind(cmd=cmd[0], timeout=timeout)

    try:
        # Create subprocess without shell (safe from injection)
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        log.debug("subprocess_started", pid=process.pid)

        # Wait for completion with timeout
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            returncode = process.returncode or 0

            log.debug(
                "subprocess_completed",
                returncode=returncode,
                stdout_len=len(stdout),
                stderr_len=len(stderr)
            )

            return stdout, stderr, returncode

        except asyncio.TimeoutError:
            # Kill process on timeout
            log.warning("subprocess_timeout", pid=process.pid)
            process.kill()
            # Wait for process to actually terminate
            await process.communicate()
            raise

    except Exception as e:
        log.error("subprocess_failed", error=str(e))
        raise


async def run_with_retry(
    cmd: list[str],
    max_retries: int = 3,
    timeout: int = 300
) -> tuple[str, str, int]:
    """Run command with retry logic for transient failures.

    Retries with exponential backoff (1s, 2s, 4s) for transient network/timeout
    errors. Does NOT retry for binary-not-found or permission errors.

    Args:
        cmd: Command and arguments as list
        max_retries: Maximum number of retry attempts (default: 3)
        timeout: Timeout per attempt in seconds (default: 300)

    Returns:
        Tuple of (stdout, stderr, returncode)

    Raises:
        Exception: If all retries exhausted or non-transient error
    """
    log = logger.bind(cmd=cmd[0], max_retries=max_retries)

    for attempt in range(max_retries):
        try:
            stdout, stderr, returncode = await run_subprocess(cmd, timeout=timeout)

            # Check if command failed with transient error
            if returncode != 0:
                stderr_lower = stderr.lower()

                # Check for permanent errors (don't retry)
                is_permanent = any(
                    keyword in stderr_lower
                    for keyword in ["not found", "permission denied", "no such file"]
                )

                if is_permanent:
                    log.error("permanent_error_in_output", stderr=stderr)
                    return stdout, stderr, returncode

                # Check for transient errors (retry)
                is_transient = any(
                    keyword in stderr_lower
                    for keyword in ["connection", "timeout", "temporary", "unavailable"]
                )

                if is_transient and attempt < max_retries - 1:
                    backoff = 2 ** attempt
                    log.warning(
                        "retry_after_transient_error_in_output",
                        attempt=attempt + 1,
                        stderr=stderr[:100],
                        backoff_seconds=backoff
                    )
                    await asyncio.sleep(backoff)
                    continue

            # Success or non-retryable failure
            return stdout, stderr, returncode

        except asyncio.TimeoutError:
            # Timeout is transient, retry
            if attempt < max_retries - 1:
                backoff = 2 ** attempt  # 1s, 2s, 4s
                log.warning(
                    "retry_after_timeout",
                    attempt=attempt + 1,
                    backoff_seconds=backoff
                )
                await asyncio.sleep(backoff)
                continue
            raise

        except Exception as e:
            error_str = str(e).lower()

            # Check if error is transient (connection/timeout related)
            is_transient = any(
                keyword in error_str
                for keyword in ["connection", "timeout", "temporary", "unavailable"]
            )

            # Check if error is permanent (binary not found, permission denied)
            is_permanent = any(
                keyword in error_str
                for keyword in ["not found", "permission denied", "no such file"]
            )

            if is_permanent:
                # Don't retry permanent errors
                log.error("permanent_error", error=str(e))
                raise

            if is_transient and attempt < max_retries - 1:
                # Retry transient errors
                backoff = 2 ** attempt
                log.warning(
                    "retry_after_transient_error",
                    attempt=attempt + 1,
                    error=str(e),
                    backoff_seconds=backoff
                )
                await asyncio.sleep(backoff)
                continue

            # Max retries exhausted or non-transient error
            raise
