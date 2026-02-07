"""ReconAgent for orchestrating reconnaissance tool pipeline.

Orchestrates subfinder -> nmap -> whatweb -> persist into a complete attack surface map.
Includes scope enforcement, graceful degradation, checkpointing, and audit logging.
"""

import json
from datetime import datetime, timezone
from sqlalchemy import select, update
import structlog

from scanner.tools import SubfinderTool, NmapTool, WhatWebTool, ToolStatus
from scanner.core.persistence.database import get_session
from scanner.core.persistence.models import Target, ScanResult
from scanner.core.safety.scope import is_in_scope
from .base import BaseAgent

logger = structlog.get_logger()


class ReconAgent(BaseAgent):
    """Orchestrates reconnaissance tools into a complete attack surface map.

    Pipeline: enumerate subdomains -> scan ports -> fingerprint technologies -> persist results

    Features:
    - Resumption from checkpoints (if interrupted mid-pipeline)
    - Scope enforcement (verifies target is authorized before scanning)
    - Audit logging of every tool invocation and result
    - Graceful degradation when tools are not installed
    - Subdomain count limiting to avoid excessive scanning
    - Structured attack surface output persisted to ScanResult
    """

    # Maximum subdomains to scan with nmap (to avoid excessive scan times)
    MAX_SUBDOMAINS_FOR_PORT_SCAN = 20

    # HTTP ports to check for web fingerprinting
    HTTP_PORTS = {80, 443, 8080, 8443, 8000, 3000}

    def __init__(self, session_id: str | None = None):
        """Initialize ReconAgent with tool wrappers.

        Args:
            session_id: Optional session ID (generates new UUID if not provided)
        """
        super().__init__(session_id)
        self.subfinder = SubfinderTool()
        self.nmap = NmapTool()
        self.whatweb = WhatWebTool()

    async def run(self, target: str, ports: str | None = None) -> dict:
        """Execute full recon pipeline on target.

        Pipeline:
        1. Scope check - verify target is authorized
        2. Subdomain enumeration - discover subdomains with subfinder
        3. Port scanning - scan ports/services with nmap
        4. Technology fingerprinting - identify web technologies with whatweb
        5. Attack surface building - consolidate all results
        6. Persistence - save to database

        Args:
            target: Domain to scan (e.g., "example.com")
            ports: Optional port specification for nmap (e.g., "80,443,8080")

        Returns:
            dict with keys:
                target: str
                subdomains: list[str]
                port_scan: list[dict]  (hosts with port/service details)
                technologies: list[dict]  (fingerprinted tech per subdomain)
                attack_surface: dict  (consolidated map)
                scan_id: str  (ScanResult.id for retrieval)

        Raises:
            RuntimeError: If target is not in authorized scope

        Example:
            >>> agent = ReconAgent()
            >>> result = await agent.run("example.com", ports="80,443")
            >>> print(f"Found {len(result['subdomains'])} subdomains")
            >>> print(f"Scan ID: {result['scan_id']}")
        """
        self.log.info("recon_start", target=target, ports=ports)

        # Step 0: Scope check
        async with get_session() as session:
            in_scope, reason = await is_in_scope(session, target)

            # Audit log scope check
            await self.audit("scope_check", {
                "target": target,
                "in_scope": in_scope,
                "reason": reason
            })

            if not in_scope:
                error_msg = f"Target not in authorized scope: {reason}"
                self.log.error("scope_denied", target=target, reason=reason)
                raise RuntimeError(error_msg)

            # Get target_id for later persistence
            result = await session.execute(
                select(Target).where(Target.url.contains(target))
            )
            target_obj = result.scalar_one_or_none()
            target_id = target_obj.id if target_obj else None

        # Check for resumption
        checkpoint_state = await self.restore()
        if checkpoint_state and checkpoint_state.get("target") == target:
            self.log.info("resuming_from_checkpoint", state=checkpoint_state)
            start_step = checkpoint_state.get("step", "subdomains")
        else:
            start_step = "subdomains"
            checkpoint_state = {"target": target, "step": "subdomains", "results": {}}

        # Step 1: Subdomain enumeration (RECON-01)
        if start_step == "subdomains":
            subdomains = await self._enumerate_subdomains(target)
            checkpoint_state["results"]["subdomains"] = subdomains
            checkpoint_state["step"] = "ports"
            await self.checkpoint(checkpoint_state, metadata="Completed subdomain enumeration")
        else:
            subdomains = checkpoint_state["results"].get("subdomains", [target])

        # Step 2: Port scanning (RECON-02)
        if start_step in ["subdomains", "ports"]:
            port_scan = await self._scan_ports(subdomains, ports)
            checkpoint_state["results"]["port_scan"] = port_scan
            checkpoint_state["step"] = "fingerprint"
            await self.checkpoint(checkpoint_state, metadata="Completed port scanning")
        else:
            port_scan = checkpoint_state["results"].get("port_scan", [])

        # Step 3: Technology fingerprinting (RECON-03)
        if start_step in ["subdomains", "ports", "fingerprint"]:
            technologies = await self._fingerprint_technologies(subdomains, port_scan)
            checkpoint_state["results"]["technologies"] = technologies
            checkpoint_state["step"] = "persist"
            await self.checkpoint(checkpoint_state, metadata="Completed technology fingerprinting")
        else:
            technologies = checkpoint_state["results"].get("technologies", [])

        # Step 4: Build attack surface and persist (RECON-04)
        attack_surface = self._build_attack_surface(
            target, subdomains, port_scan, technologies
        )

        scan_id = await self._persist_results(target_id, attack_surface)

        self.log.info("recon_complete", target=target, scan_id=scan_id)

        # Return flattened services list as port_scan for easier CLI consumption
        return {
            "target": target,
            "subdomains": subdomains,
            "port_scan": attack_surface["services"],  # Use flattened services
            "technologies": technologies,
            "attack_surface": attack_surface,
            "scan_id": scan_id
        }

    async def _enumerate_subdomains(self, target: str) -> list[str]:
        """Enumerate subdomains using subfinder.

        Handles missing tool gracefully by falling back to base domain.

        Args:
            target: Domain to enumerate

        Returns:
            List of discovered subdomains (deduplicated)
        """
        self.log.info("subdomain_enum_start", target=target)

        result = await self.subfinder.run(target)

        if result.status == ToolStatus.NOT_INSTALLED:
            self.log.warning("subfinder_not_installed", using_fallback=True)
            await self.audit("subdomain_enum", {
                "tool": "subfinder",
                "status": "not_installed",
                "fallback": [target]
            })
            return [target]

        if result.status in [ToolStatus.ERROR, ToolStatus.TIMEOUT]:
            self.log.error("subfinder_failed", status=result.status, error=result.error)
            await self.audit("subdomain_enum", {
                "tool": "subfinder",
                "status": result.status.value,
                "error": result.error,
                "fallback": [target]
            })
            return [target]

        subdomains = result.data.get("subdomains", [target])

        await self.audit("subdomain_enum", {
            "tool": "subfinder",
            "status": "success",
            "count": len(subdomains),
            "duration": result.duration_seconds
        })

        self.log.info("subdomain_enum_complete", count=len(subdomains))
        return subdomains

    async def _scan_ports(self, subdomains: list[str], ports: str | None) -> list[dict]:
        """Scan ports on subdomains using nmap.

        Limits to MAX_SUBDOMAINS_FOR_PORT_SCAN to avoid excessive scanning.
        Handles missing tool gracefully by returning empty results.

        Args:
            subdomains: List of subdomains to scan
            ports: Optional port specification (e.g., "80,443")

        Returns:
            List of host dictionaries with port/service data
        """
        self.log.info("port_scan_start", subdomain_count=len(subdomains))

        # Limit subdomains to scan
        if len(subdomains) > self.MAX_SUBDOMAINS_FOR_PORT_SCAN:
            self.log.warning(
                "limiting_port_scan",
                total=len(subdomains),
                limit=self.MAX_SUBDOMAINS_FOR_PORT_SCAN
            )
            subdomains_to_scan = subdomains[:self.MAX_SUBDOMAINS_FOR_PORT_SCAN]
        else:
            subdomains_to_scan = subdomains

        if self.nmap.is_available():
            port_scan = []

            for subdomain in subdomains_to_scan:
                result = await self.nmap.run(subdomain, ports=ports)

                if result.status == ToolStatus.SUCCESS:
                    port_scan.extend(result.data.get("hosts", []))

            total_ports = sum(len(host["ports"]) for host in port_scan)

            await self.audit("port_scan", {
                "tool": "nmap",
                "status": "success",
                "targets_scanned": len(subdomains_to_scan),
                "total_open_ports": total_ports
            })

            self.log.info("port_scan_complete", hosts=len(port_scan), ports=total_ports)
            return port_scan
        else:
            self.log.warning("nmap_not_installed", using_empty_results=True)
            await self.audit("port_scan", {
                "tool": "nmap",
                "status": "not_installed",
                "targets_scanned": 0,
                "total_open_ports": 0
            })
            return []

    async def _fingerprint_technologies(
        self,
        subdomains: list[str],
        port_scan: list[dict]
    ) -> list[dict]:
        """Fingerprint web technologies using whatweb.

        Scans subdomains that have open HTTP ports, or all subdomains if port scan was skipped.
        Handles missing tool gracefully by returning empty results.

        Args:
            subdomains: List of subdomains
            port_scan: Port scan results (to identify HTTP services)

        Returns:
            List of technology dictionaries (aggregated across all subdomains)
        """
        self.log.info("fingerprint_start", subdomain_count=len(subdomains))

        # Determine which subdomains to fingerprint
        if port_scan:
            # Only scan subdomains with open HTTP ports
            targets_to_fingerprint = set()
            for host_data in port_scan:
                for port_data in host_data.get("ports", []):
                    if port_data.get("port") in self.HTTP_PORTS and port_data.get("state") == "open":
                        targets_to_fingerprint.add(host_data["address"])
            targets_to_fingerprint = list(targets_to_fingerprint)
        else:
            # No port scan - try all subdomains
            targets_to_fingerprint = subdomains

        if not self.whatweb.is_available():
            self.log.warning("whatweb_not_installed", using_empty_results=True)
            await self.audit("fingerprint", {
                "tool": "whatweb",
                "status": "not_installed",
                "targets_scanned": 0,
                "technologies_found": 0
            })
            return []

        all_technologies = []

        for subdomain in targets_to_fingerprint:
            result = await self.whatweb.run(subdomain)

            if result.status == ToolStatus.SUCCESS:
                techs = result.data.get("technologies", [])
                # Add subdomain to each technology entry
                for tech in techs:
                    tech["subdomain"] = subdomain
                all_technologies.extend(techs)

        # Deduplicate technologies by (name, version, subdomain)
        unique_techs = []
        seen = set()
        for tech in all_technologies:
            key = (tech["name"], tech.get("version"), tech.get("subdomain"))
            if key not in seen:
                seen.add(key)
                unique_techs.append(tech)

        await self.audit("fingerprint", {
            "tool": "whatweb",
            "status": "success",
            "targets_scanned": len(targets_to_fingerprint),
            "technologies_found": len(unique_techs)
        })

        self.log.info("fingerprint_complete", technologies=len(unique_techs))
        return unique_techs

    def _build_attack_surface(
        self,
        target: str,
        subdomains: list[str],
        port_scan: list[dict],
        technologies: list[dict]
    ) -> dict:
        """Build consolidated attack surface map.

        Combines all reconnaissance results into a single structured map.

        Args:
            target: Base target domain
            subdomains: Discovered subdomains
            port_scan: Port/service data
            technologies: Technology fingerprints

        Returns:
            Attack surface dictionary with timestamp and summary
        """
        # Flatten port scan into services list
        services = []
        for host_data in port_scan:
            for port_data in host_data.get("ports", []):
                services.append({
                    "host": host_data["address"],
                    "port": port_data["port"],
                    "protocol": port_data["protocol"],
                    "state": port_data["state"],
                    "service": port_data["service"],
                    "version": port_data.get("version", "")
                })

        attack_surface = {
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "subdomains": subdomains,
            "services": services,
            "technologies": technologies,
            "summary": {
                "total_subdomains": len(subdomains),
                "total_open_ports": len([s for s in services if s["state"] == "open"]),
                "total_technologies": len(technologies),
                "total_services": len(services)
            }
        }

        return attack_surface

    async def _persist_results(self, target_id: str | None, attack_surface: dict) -> str:
        """Persist attack surface to database.

        Creates ScanResult record and updates Target.last_scanned.

        Args:
            target_id: Target ID from database (can be None if target not found)
            attack_surface: Attack surface dictionary

        Returns:
            scan_id (ScanResult.id)
        """
        self.log.info("persisting_results")

        async with get_session() as session:
            # Create ScanResult
            scan_result = ScanResult(
                session_id=self.session_id,
                target_id=target_id or "unknown",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                findings=json.dumps(attack_surface),
                status="completed"
            )

            session.add(scan_result)
            await session.flush()  # Get scan_result.id

            # Update Target.last_scanned if target exists
            if target_id:
                await session.execute(
                    update(Target)
                    .where(Target.id == target_id)
                    .values(last_scanned=datetime.now(timezone.utc))
                )

            scan_id = scan_result.id

        await self.audit("recon_complete", {
            "attack_surface_summary": attack_surface["summary"],
            "scan_id": scan_id
        })

        self.log.info("results_persisted", scan_id=scan_id)
        return scan_id
