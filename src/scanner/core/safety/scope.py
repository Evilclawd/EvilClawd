"""Scope enforcement for authorized targets (SAFE-01).

Ensures that all tool execution checks the target against authorized scope
before running. Targets must be explicitly added to the database before
any scanning operations can proceed.

Provides:
- ScopeChecker: Class-based scope enforcement with database session
- is_in_scope: Helper function for quick scope checking
"""

import json
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanner.core.persistence.models import Target


class ScopeChecker:
    """Enforce that targets are explicitly authorized (SAFE-01).

    Queries the Target table to verify that a given URL or hostname
    has been authorized for scanning, and that the specific path/subdomain
    falls within the defined scope patterns.
    """

    def __init__(self, session: AsyncSession):
        """Initialize scope checker with database session.

        Args:
            session: Async database session for querying authorized targets
        """
        self.session = session

    async def is_in_scope(self, target: str) -> tuple[bool, str | None]:
        """Check if target is authorized for scanning.

        Parses the target URL to extract the hostname, queries the database
        for matching authorized targets, and validates against scope patterns.

        Args:
            target: URL or hostname to check (e.g., "https://example.com/api"
                    or "example.com")

        Returns:
            Tuple of (is_authorized, reason_if_denied).
            If authorized: (True, None)
            If denied: (False, "explanation string")
        """
        # Parse target URL
        parsed = urlparse(target if "://" in target else f"https://{target}")
        hostname = parsed.hostname or target

        # Query for matching authorized target
        result = await self.session.execute(
            select(Target).where(Target.url.contains(hostname))
        )
        authorized_target = result.scalar_one_or_none()

        if not authorized_target:
            return False, f"Target {hostname} not in authorized scope"

        # Check scope constraints (JSON list of allowed patterns)
        scope_patterns = json.loads(authorized_target.scope)

        # Simple containment check (Phase 2 will add wildcard/regex support)
        if not any(pattern in target for pattern in scope_patterns):
            return False, f"Target {target} outside scope {scope_patterns}"

        return True, None


async def is_in_scope(session: AsyncSession, target: str) -> tuple[bool, str | None]:
    """Helper function for scope checking.

    Convenience wrapper around ScopeChecker for one-off scope checks
    without needing to instantiate the class.

    Args:
        session: Async database session
        target: URL or hostname to check

    Returns:
        Tuple of (is_authorized, reason_if_denied)
    """
    checker = ScopeChecker(session)
    return await checker.is_in_scope(target)
