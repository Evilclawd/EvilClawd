"""WhatWeb tool wrapper for web technology fingerprinting (RECON-03).

Wraps the whatweb binary to identify web technologies on targets.
Parses JSON output and returns structured technology data.
"""

import json
import time
import structlog
from .base import Tool, ToolResult, ToolStatus, check_binary, run_with_retry

logger = structlog.get_logger()


# Technology category mapping
TECH_CATEGORIES = {
    # Web servers
    "Apache": "web-server",
    "Nginx": "web-server",
    "IIS": "web-server",
    "LiteSpeed": "web-server",
    "Caddy": "web-server",

    # CMS
    "WordPress": "cms",
    "Drupal": "cms",
    "Joomla": "cms",
    "Magento": "cms",

    # Frameworks
    "Laravel": "framework",
    "Django": "framework",
    "Flask": "framework",
    "Ruby-on-Rails": "framework",
    "Express": "framework",
    "React": "framework",
    "Vue": "framework",
    "Angular": "framework",

    # Programming languages
    "PHP": "language",
    "Python": "language",
    "Ruby": "language",
    "Node.js": "language",

    # CDN
    "Cloudflare": "cdn",
    "Akamai": "cdn",
    "Fastly": "cdn",

    # Analytics
    "Google-Analytics": "analytics",
    "Google-Tag-Manager": "analytics",

    # JavaScript libraries
    "jQuery": "javascript-library",
    "Bootstrap": "javascript-library",
}


class WhatWebTool:
    """Wrapper for whatweb web technology fingerprinting tool.

    Runs whatweb with JSON output and parses discovered technologies.
    Handles missing binary gracefully with install instructions.
    """

    name = "whatweb"
    binary_name = "whatweb"

    def __init__(self, timeout: int = 300):
        """Initialize whatweb tool wrapper.

        Args:
            timeout: Timeout in seconds for whatweb execution (default: 300)
        """
        self.timeout = timeout
        self.log = logger.bind(tool=self.name)

    def is_available(self) -> bool:
        """Check if whatweb binary is available on PATH.

        Returns:
            True if whatweb is installed, False otherwise
        """
        return check_binary(self.binary_name)

    async def run(self, target: str, **kwargs) -> ToolResult:
        """Fingerprint web technologies on target.

        Runs: whatweb --log-json=- <target_url>

        Args:
            target: URL or hostname to fingerprint
            **kwargs: Additional arguments (currently unused)

        Returns:
            ToolResult with data:
                technologies: list[dict] - each dict has:
                    name: str           - technology name (e.g., "Apache", "WordPress")
                    version: str | None - version if detected
                    category: str       - category (e.g., "web-server", "cms")
                url: str               - the URL that was scanned

        Example:
            >>> tool = WhatWebTool()
            >>> result = await tool.run("example.com")
            >>> for tech in result.data["technologies"]:
            ...     print(f"{tech['name']} {tech['version']} ({tech['category']})")
        """
        start_time = time.time()
        self.log.info("whatweb_start", target=target)

        # Check if binary is available
        if not self.is_available():
            error_msg = (
                f"{self.binary_name} not installed. "
                "Install: brew install whatweb (macOS) or apt-get install whatweb (Linux)"
            )
            self.log.warning("binary_not_found", binary=self.binary_name)
            return ToolResult(
                status=ToolStatus.NOT_INSTALLED,
                error=error_msg,
                duration_seconds=time.time() - start_time
            )

        # Ensure target has scheme
        target_url = target
        if not target.startswith("http://") and not target.startswith("https://"):
            target_url = f"https://{target}"

        # Build command
        cmd = [
            self.binary_name,
            "--log-json=-",  # Output JSON to stdout
            "--color=never",  # No color codes
            target_url
        ]

        try:
            # Execute with retry for transient failures
            stdout, stderr, returncode = await run_with_retry(
                cmd,
                timeout=self.timeout
            )

            # WhatWeb can return non-zero for connection errors but still output JSON
            # Parse output even if returncode != 0

            # Parse JSON output
            technologies = self._parse_json_output(stdout)

            if returncode != 0 and not technologies:
                # Failed with no results
                error_msg = f"whatweb failed with code {returncode}: {stderr}"
                self.log.error("whatweb_failed", returncode=returncode, stderr=stderr)
                return ToolResult(
                    status=ToolStatus.ERROR,
                    error=error_msg,
                    raw_output=stdout,
                    duration_seconds=time.time() - start_time
                )

            duration = time.time() - start_time
            self.log.info(
                "whatweb_complete",
                target=target_url,
                technologies=len(technologies),
                duration=duration
            )

            return ToolResult(
                status=ToolStatus.SUCCESS,
                data={
                    "technologies": technologies,
                    "url": target_url
                },
                raw_output=stdout,
                duration_seconds=duration
            )

        except Exception as e:
            error_msg = f"whatweb execution error: {str(e)}"
            self.log.error("whatweb_exception", error=str(e))
            return ToolResult(
                status=ToolStatus.ERROR,
                error=error_msg,
                duration_seconds=time.time() - start_time
            )

    def _parse_json_output(self, json_output: str) -> list[dict]:
        """Parse whatweb JSON output into structured technology data.

        Args:
            json_output: Raw JSON output from whatweb (one or more JSON objects)

        Returns:
            List of technology dictionaries
        """
        technologies = []

        # WhatWeb outputs JSON as one or more JSON objects (not always valid JSON array)
        for line in json_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)

                # Extract plugins (technologies)
                plugins = data.get("plugins", {})

                for plugin_name, plugin_data in plugins.items():
                    # Skip generic/unhelpful plugins
                    if plugin_name in ["Country", "IP", "HTTPServer"]:
                        continue

                    # Extract version if available
                    version = None
                    if isinstance(plugin_data, dict):
                        # Check for version in various fields
                        if "version" in plugin_data:
                            version_data = plugin_data["version"]
                            if isinstance(version_data, list) and version_data:
                                version = version_data[0]
                            elif isinstance(version_data, str):
                                version = version_data
                        elif "string" in plugin_data:
                            string_data = plugin_data["string"]
                            if isinstance(string_data, list) and string_data:
                                version = string_data[0]
                            elif isinstance(string_data, str):
                                version = string_data

                    # Determine category
                    category = TECH_CATEGORIES.get(plugin_name, "unknown")

                    technologies.append({
                        "name": plugin_name,
                        "version": version,
                        "category": category
                    })

            except json.JSONDecodeError:
                # Skip malformed lines
                self.log.warning("json_parse_error", line=line[:100])
                continue

        return technologies
