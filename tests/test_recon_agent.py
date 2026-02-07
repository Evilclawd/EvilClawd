"""Unit tests for ReconAgent orchestration.

Tests the full reconnaissance pipeline with mocked tools and database.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from scanner.agents import ReconAgent, BaseAgent
from scanner.tools import ToolStatus, ToolResult


# Mock tool results
MOCK_SUBFINDER_SUCCESS = ToolResult(
    status=ToolStatus.SUCCESS,
    data={
        "subdomains": ["example.com", "www.example.com", "api.example.com"],
        "count": 3
    },
    duration_seconds=2.5
)

MOCK_NMAP_SUCCESS = ToolResult(
    status=ToolStatus.SUCCESS,
    data={
        "hosts": [
            {
                "address": "example.com",
                "ports": [
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "nginx 1.19.0"},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.19.0"}
                ]
            }
        ]
    },
    duration_seconds=15.3
)

MOCK_WHATWEB_SUCCESS = ToolResult(
    status=ToolStatus.SUCCESS,
    data={
        "technologies": [
            {"name": "nginx", "version": "1.19.0", "category": "web-server"},
            {"name": "WordPress", "version": None, "category": "cms"}
        ],
        "url": "https://example.com"
    },
    duration_seconds=3.2
)


@pytest.mark.asyncio
async def test_recon_agent_full_pipeline():
    """Test complete ReconAgent pipeline with all tools successful."""
    agent = ReconAgent()

    # Mock is_in_scope
    mock_scope_result = (True, None)

    # Mock Target object
    mock_target = MagicMock()
    mock_target.id = "target-123"

    # Mock database session and queries
    with patch("scanner.agents.recon.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        # Mock scope check
        with patch("scanner.agents.recon.is_in_scope", return_value=mock_scope_result):
            # Mock target query
            mock_execute_result = MagicMock()
            mock_execute_result.scalar_one_or_none.return_value = mock_target
            mock_session.execute = AsyncMock(return_value=mock_execute_result)

            # Mock tools
            with patch.object(agent.subfinder, "run", return_value=MOCK_SUBFINDER_SUCCESS):
                with patch.object(agent.nmap, "run", return_value=MOCK_NMAP_SUCCESS):
                    with patch.object(agent.nmap, "is_available", return_value=True):
                        with patch.object(agent.whatweb, "run", return_value=MOCK_WHATWEB_SUCCESS):
                            with patch.object(agent.whatweb, "is_available", return_value=True):
                                # Mock audit and checkpoint
                                with patch.object(agent, "audit", new_callable=AsyncMock):
                                    with patch.object(agent, "checkpoint", new_callable=AsyncMock):
                                        with patch.object(agent, "restore", return_value=None):
                                            result = await agent.run("example.com")

    # Verify result structure
    assert "target" in result
    assert result["target"] == "example.com"
    assert "subdomains" in result
    assert len(result["subdomains"]) == 3
    assert "port_scan" in result
    # port_scan now returns flattened services (3 hosts × 2 ports each = 6 services)
    assert len(result["port_scan"]) == 6
    assert "technologies" in result
    # Technologies can be deduplicated, so just verify we have some
    assert len(result["technologies"]) >= 1
    assert "attack_surface" in result
    assert "scan_id" in result

    # Verify attack surface structure
    attack_surface = result["attack_surface"]
    assert "target" in attack_surface
    assert "timestamp" in attack_surface
    assert "subdomains" in attack_surface
    assert "services" in attack_surface
    assert "technologies" in attack_surface
    assert "summary" in attack_surface

    # Verify summary statistics
    summary = attack_surface["summary"]
    assert summary["total_subdomains"] == 3
    # Each subdomain got scanned, so total_open_ports is 2 per subdomain = 6
    assert summary["total_open_ports"] == 6
    assert summary["total_technologies"] >= 1


@pytest.mark.asyncio
async def test_recon_agent_scope_check_fails():
    """Test that ReconAgent raises RuntimeError when target is not in scope."""
    agent = ReconAgent()

    # Mock is_in_scope returning False
    mock_scope_result = (False, "Not authorized")

    with patch("scanner.agents.recon.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.recon.is_in_scope", return_value=mock_scope_result):
            with patch.object(agent, "audit", new_callable=AsyncMock):
                with pytest.raises(RuntimeError) as exc_info:
                    await agent.run("unauthorized.com")

                assert "not in authorized scope" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_recon_agent_handles_missing_subfinder():
    """Test that ReconAgent falls back to base domain when subfinder is not installed."""
    agent = ReconAgent()

    mock_subfinder_not_installed = ToolResult(
        status=ToolStatus.NOT_INSTALLED,
        error="subfinder not installed"
    )

    mock_target = MagicMock()
    mock_target.id = "target-123"

    with patch("scanner.agents.recon.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.recon.is_in_scope", return_value=(True, None)):
            mock_execute_result = MagicMock()
            mock_execute_result.scalar_one_or_none.return_value = mock_target
            mock_session.execute = AsyncMock(return_value=mock_execute_result)

            with patch.object(agent.subfinder, "run", return_value=mock_subfinder_not_installed):
                with patch.object(agent.nmap, "run", return_value=MOCK_NMAP_SUCCESS):
                    with patch.object(agent.nmap, "is_available", return_value=True):
                        with patch.object(agent.whatweb, "run", return_value=MOCK_WHATWEB_SUCCESS):
                            with patch.object(agent.whatweb, "is_available", return_value=True):
                                with patch.object(agent, "audit", new_callable=AsyncMock):
                                    with patch.object(agent, "checkpoint", new_callable=AsyncMock):
                                        with patch.object(agent, "restore", return_value=None):
                                            result = await agent.run("example.com")

    # Should fall back to base domain only
    assert result["subdomains"] == ["example.com"]
    assert "attack_surface" in result


@pytest.mark.asyncio
async def test_recon_agent_handles_missing_nmap():
    """Test that ReconAgent continues with empty port data when nmap is not installed."""
    agent = ReconAgent()

    mock_target = MagicMock()
    mock_target.id = "target-123"

    with patch("scanner.agents.recon.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.recon.is_in_scope", return_value=(True, None)):
            mock_execute_result = MagicMock()
            mock_execute_result.scalar_one_or_none.return_value = mock_target
            mock_session.execute = AsyncMock(return_value=mock_execute_result)

            with patch.object(agent.subfinder, "run", return_value=MOCK_SUBFINDER_SUCCESS):
                with patch.object(agent.nmap, "is_available", return_value=False):
                    with patch.object(agent.whatweb, "run", return_value=MOCK_WHATWEB_SUCCESS):
                        with patch.object(agent.whatweb, "is_available", return_value=True):
                            with patch.object(agent, "audit", new_callable=AsyncMock):
                                with patch.object(agent, "checkpoint", new_callable=AsyncMock):
                                    with patch.object(agent, "restore", return_value=None):
                                        result = await agent.run("example.com")

    # Should have empty port scan results
    assert result["port_scan"] == []
    assert result["attack_surface"]["summary"]["total_open_ports"] == 0


@pytest.mark.asyncio
async def test_recon_agent_handles_missing_whatweb():
    """Test that ReconAgent continues with empty tech data when whatweb is not installed."""
    agent = ReconAgent()

    mock_target = MagicMock()
    mock_target.id = "target-123"

    with patch("scanner.agents.recon.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.recon.is_in_scope", return_value=(True, None)):
            mock_execute_result = MagicMock()
            mock_execute_result.scalar_one_or_none.return_value = mock_target
            mock_session.execute = AsyncMock(return_value=mock_execute_result)

            with patch.object(agent.subfinder, "run", return_value=MOCK_SUBFINDER_SUCCESS):
                with patch.object(agent.nmap, "run", return_value=MOCK_NMAP_SUCCESS):
                    with patch.object(agent.nmap, "is_available", return_value=True):
                        with patch.object(agent.whatweb, "is_available", return_value=False):
                            with patch.object(agent, "audit", new_callable=AsyncMock):
                                with patch.object(agent, "checkpoint", new_callable=AsyncMock):
                                    with patch.object(agent, "restore", return_value=None):
                                        result = await agent.run("example.com")

    # Should have empty technology results
    assert result["technologies"] == []
    assert result["attack_surface"]["summary"]["total_technologies"] == 0


@pytest.mark.asyncio
async def test_recon_agent_limits_subdomains():
    """Test that ReconAgent limits subdomain count for port scanning."""
    agent = ReconAgent()

    # Create mock result with 100 subdomains
    many_subdomains = [f"sub{i}.example.com" for i in range(100)]
    mock_subfinder_many = ToolResult(
        status=ToolStatus.SUCCESS,
        data={"subdomains": many_subdomains, "count": 100},
        duration_seconds=5.0
    )

    mock_target = MagicMock()
    mock_target.id = "target-123"

    nmap_call_count = 0

    async def count_nmap_calls(*args, **kwargs):
        nonlocal nmap_call_count
        nmap_call_count += 1
        return MOCK_NMAP_SUCCESS

    with patch("scanner.agents.recon.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.recon.is_in_scope", return_value=(True, None)):
            mock_execute_result = MagicMock()
            mock_execute_result.scalar_one_or_none.return_value = mock_target
            mock_session.execute = AsyncMock(return_value=mock_execute_result)

            with patch.object(agent.subfinder, "run", return_value=mock_subfinder_many):
                with patch.object(agent.nmap, "run", side_effect=count_nmap_calls):
                    with patch.object(agent.nmap, "is_available", return_value=True):
                        with patch.object(agent.whatweb, "is_available", return_value=False):
                            with patch.object(agent, "audit", new_callable=AsyncMock):
                                with patch.object(agent, "checkpoint", new_callable=AsyncMock):
                                    with patch.object(agent, "restore", return_value=None):
                                        result = await agent.run("example.com")

    # Should only scan MAX_SUBDOMAINS_FOR_PORT_SCAN (20)
    assert nmap_call_count == 20
    assert len(result["subdomains"]) == 100  # All subdomains in result
    assert result["attack_surface"]["summary"]["total_subdomains"] == 100


@pytest.mark.asyncio
async def test_recon_agent_attack_surface_structure():
    """Test that attack surface has all required fields and correct structure."""
    agent = ReconAgent()

    mock_target = MagicMock()
    mock_target.id = "target-123"

    with patch("scanner.agents.recon.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.recon.is_in_scope", return_value=(True, None)):
            mock_execute_result = MagicMock()
            mock_execute_result.scalar_one_or_none.return_value = mock_target
            mock_session.execute = AsyncMock(return_value=mock_execute_result)

            with patch.object(agent.subfinder, "run", return_value=MOCK_SUBFINDER_SUCCESS):
                with patch.object(agent.nmap, "run", return_value=MOCK_NMAP_SUCCESS):
                    with patch.object(agent.nmap, "is_available", return_value=True):
                        with patch.object(agent.whatweb, "run", return_value=MOCK_WHATWEB_SUCCESS):
                            with patch.object(agent.whatweb, "is_available", return_value=True):
                                with patch.object(agent, "audit", new_callable=AsyncMock):
                                    with patch.object(agent, "checkpoint", new_callable=AsyncMock):
                                        with patch.object(agent, "restore", return_value=None):
                                            result = await agent.run("example.com")

    attack_surface = result["attack_surface"]

    # Verify required top-level keys
    required_keys = ["target", "timestamp", "subdomains", "services", "technologies", "summary"]
    for key in required_keys:
        assert key in attack_surface, f"Missing required key: {key}"

    # Verify summary has all required stats
    summary = attack_surface["summary"]
    required_summary_keys = ["total_subdomains", "total_open_ports", "total_technologies", "total_services"]
    for key in required_summary_keys:
        assert key in summary, f"Missing required summary key: {key}"

    # Verify services are properly flattened
    services = attack_surface["services"]
    assert isinstance(services, list)
    if services:
        service = services[0]
        assert "host" in service
        assert "port" in service
        assert "protocol" in service
        assert "state" in service
        assert "service" in service


@pytest.mark.asyncio
async def test_base_agent_audit():
    """Test that BaseAgent audit logging works."""
    agent = BaseAgent()

    with patch("scanner.agents.base.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.base.append_audit_log", new_callable=AsyncMock) as mock_append:
            await agent.audit("test_event", {"key": "value"})

            # Verify append_audit_log was called with correct arguments
            mock_append.assert_called_once()
            call_args = mock_append.call_args
            assert call_args[1]["event_type"] == "test_event"
            assert call_args[1]["session_id"] == agent.session_id
            assert call_args[1]["actor"] == "agent"
            assert call_args[1]["event_data"] == {"key": "value"}


@pytest.mark.asyncio
async def test_base_agent_checkpoint():
    """Test that BaseAgent checkpointing works."""
    agent = BaseAgent()

    with patch("scanner.agents.base.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.base.save_checkpoint", new_callable=AsyncMock, return_value=42) as mock_save:
            checkpoint_id = await agent.checkpoint({"step": 1}, metadata="Test checkpoint")

            # Verify save_checkpoint was called
            assert checkpoint_id == 42
            mock_save.assert_called_once()
            call_args = mock_save.call_args
            assert call_args[1]["session_id"] == agent.session_id
            assert call_args[1]["state"] == {"step": 1}
            assert call_args[1]["checkpoint_metadata"] == "Test checkpoint"


@pytest.mark.asyncio
async def test_base_agent_restore():
    """Test that BaseAgent restore works."""
    agent = BaseAgent()

    with patch("scanner.agents.base.get_session") as mock_get_session:
        mock_session = AsyncMock()
        mock_get_session.return_value.__aenter__.return_value = mock_session

        with patch("scanner.agents.base.load_latest_checkpoint", new_callable=AsyncMock, return_value=({"step": 2}, 42)):
            state = await agent.restore()

            assert state == {"step": 2}
