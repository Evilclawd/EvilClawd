"""Nmap tool wrapper for port scanning and service detection (RECON-02).

Wraps the nmap binary to scan ports and identify services on targets.
Parses XML output and returns structured port/service data.
"""

import asyncio
import time
import xml.etree.ElementTree as ET
import structlog
from .base import Tool, ToolResult, ToolStatus, check_binary, run_with_retry

logger = structlog.get_logger()


class NmapTool:
    """Wrapper for nmap port scanning and service detection tool.

    Runs nmap with XML output and parses discovered ports/services.
    Handles missing binary gracefully with install instructions.
    Includes semaphore for concurrency limiting.
    """

    name = "nmap"
    binary_name = "nmap"

    def __init__(self, timeout: int = 600, max_concurrent: int = 10):
        """Initialize nmap tool wrapper.

        Args:
            timeout: Timeout in seconds for nmap execution (default: 600)
            max_concurrent: Maximum concurrent nmap scans (default: 10)
        """
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.log = logger.bind(tool=self.name)

    def is_available(self) -> bool:
        """Check if nmap binary is available on PATH.

        Returns:
            True if nmap is installed, False otherwise
        """
        return check_binary(self.binary_name)

    async def run(self, target: str, **kwargs) -> ToolResult:
        """Scan ports and identify services on target.

        Runs: nmap -sV -oX - <target>  (XML output to stdout)

        Args:
            target: Host or IP to scan (e.g., "example.com", "192.168.1.1")
            **kwargs:
                ports: str - port spec like "80,443" or "1-1000" (passed as -p)
                scan_type: str - "syn", "tcp", "version" (default: version/-sV)

        Returns:
            ToolResult with data:
                hosts: list[dict] - each dict has:
                    address: str
                    ports: list[dict] - each port dict has:
                        port: int
                        protocol: str (tcp/udp)
                        state: str (open/closed/filtered)
                        service: str (service name)
                        version: str (service version if detected)

        Example:
            >>> tool = NmapTool()
            >>> result = await tool.run("example.com", ports="80,443")
            >>> for host in result.data["hosts"]:
            ...     print(f"Host: {host['address']}")
            ...     for port in host['ports']:
            ...         print(f"  Port {port['port']}: {port['service']}")
        """
        start_time = time.time()
        self.log.info("nmap_start", target=target, kwargs=kwargs)

        # Check if binary is available
        if not self.is_available():
            error_msg = (
                f"{self.binary_name} not installed. "
                "Install: brew install nmap (macOS) or apt-get install nmap (Linux)"
            )
            self.log.warning("binary_not_found", binary=self.binary_name)
            return ToolResult(
                status=ToolStatus.NOT_INSTALLED,
                error=error_msg,
                duration_seconds=time.time() - start_time
            )

        # Build command
        cmd = [self.binary_name, "-sV", "-oX", "-"]

        # Add port specification if provided
        if "ports" in kwargs and kwargs["ports"]:
            cmd.extend(["-p", kwargs["ports"]])

        # Add target
        cmd.append(target)

        try:
            # Use semaphore to limit concurrent scans
            async with self.semaphore:
                # Execute with retry for transient failures
                stdout, stderr, returncode = await run_with_retry(
                    cmd,
                    timeout=self.timeout
                )

                # Check if nmap requires root for SYN scan
                if returncode != 0 and "requires root" in stderr.lower():
                    # Retry with TCP connect scan (-sT) instead
                    self.log.warning("nmap_requires_root", retrying_with_tcp=True)
                    cmd_tcp = [self.binary_name, "-sT", "-oX", "-"]
                    if "ports" in kwargs and kwargs["ports"]:
                        cmd_tcp.extend(["-p", kwargs["ports"]])
                    cmd_tcp.append(target)

                    stdout, stderr, returncode = await run_with_retry(
                        cmd_tcp,
                        timeout=self.timeout
                    )

                if returncode != 0:
                    error_msg = f"nmap failed with code {returncode}: {stderr}"
                    self.log.error("nmap_failed", returncode=returncode, stderr=stderr)
                    return ToolResult(
                        status=ToolStatus.ERROR,
                        error=error_msg,
                        raw_output=stdout,
                        duration_seconds=time.time() - start_time
                    )

                # Parse XML output
                hosts = self._parse_xml_output(stdout)

                duration = time.time() - start_time
                total_ports = sum(len(host["ports"]) for host in hosts)
                self.log.info(
                    "nmap_complete",
                    target=target,
                    hosts=len(hosts),
                    ports=total_ports,
                    duration=duration
                )

                return ToolResult(
                    status=ToolStatus.SUCCESS,
                    data={"hosts": hosts},
                    raw_output=stdout,
                    duration_seconds=duration
                )

        except Exception as e:
            error_msg = f"nmap execution error: {str(e)}"
            self.log.error("nmap_exception", error=str(e))
            return ToolResult(
                status=ToolStatus.ERROR,
                error=error_msg,
                duration_seconds=time.time() - start_time
            )

    def _parse_xml_output(self, xml_output: str) -> list[dict]:
        """Parse nmap XML output into structured data.

        Args:
            xml_output: Raw XML output from nmap

        Returns:
            List of host dictionaries with port/service information
        """
        hosts = []

        try:
            root = ET.fromstring(xml_output)

            # Find all host elements
            for host_elem in root.findall(".//host"):
                # Get host address
                address_elem = host_elem.find(".//address[@addrtype='ipv4']")
                if address_elem is None:
                    address_elem = host_elem.find(".//address[@addrtype='ipv6']")
                if address_elem is None:
                    address_elem = host_elem.find(".//address")

                if address_elem is None:
                    continue

                address = address_elem.get("addr", "unknown")

                # Get hostname if available
                hostname_elem = host_elem.find(".//hostname")
                if hostname_elem is not None:
                    hostname = hostname_elem.get("name")
                    if hostname:
                        address = hostname

                # Parse ports
                ports = []
                for port_elem in host_elem.findall(".//port"):
                    port_id = port_elem.get("portid")
                    protocol = port_elem.get("protocol", "tcp")

                    # Get port state
                    state_elem = port_elem.find("state")
                    state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                    # Get service information
                    service_elem = port_elem.find("service")
                    service_name = "unknown"
                    service_version = ""

                    if service_elem is not None:
                        service_name = service_elem.get("name", "unknown")
                        # Build version string from available info
                        version_parts = []
                        if service_elem.get("product"):
                            version_parts.append(service_elem.get("product"))
                        if service_elem.get("version"):
                            version_parts.append(service_elem.get("version"))
                        if service_elem.get("extrainfo"):
                            version_parts.append(f"({service_elem.get('extrainfo')})")
                        service_version = " ".join(version_parts)

                    ports.append({
                        "port": int(port_id) if port_id else 0,
                        "protocol": protocol,
                        "state": state,
                        "service": service_name,
                        "version": service_version
                    })

                if ports:  # Only include hosts with ports
                    hosts.append({
                        "address": address,
                        "ports": ports
                    })

        except ET.ParseError as e:
            self.log.error("xml_parse_error", error=str(e))

        return hosts
