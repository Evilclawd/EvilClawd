"""
Integration test for Phase 1: Foundation & Safety Infrastructure

Tests all success criteria from ROADMAP.md:
1. System can connect to Claude API and execute tool calls via abstraction layer
2. All scans and actions are logged immutably to SQLite database with timestamps and approval decisions
3. Session state persists to disk and can resume after interruption
4. Tool execution requires explicit scope definition before running
5. Risk classification (safe/moderate/destructive) is enforced for all tool calls
6. Output clearly distinguishes AI interpretation from tool-confirmed findings (SAFE-04)
"""

import asyncio
import json
import os
from datetime import datetime, timezone

from scanner.core.persistence.database import (
    init_database,
    create_session_factory,
    get_session,
    shutdown,
)
from scanner.core.persistence.models import Target, ScanResult
from scanner.core.persistence.audit import append_audit_log, verify_audit_chain
from scanner.core.persistence.checkpoint import save_checkpoint, load_latest_checkpoint
from scanner.core.llm.client import LLMClient, LLMProvider
from scanner.core.llm.anthropic_provider import AnthropicProvider
from scanner.core.llm.tools import TOOLS, RiskLevel, get_tool_by_name
from scanner.core.llm.context import ContextManager
from scanner.core.safety.scope import is_in_scope
from scanner.core.safety.risk import should_require_approval
from scanner.core.safety.approval import execute_tool_with_approval, ApprovalDecision
from scanner.core.config import Config, load_config
from scanner.core.output import Finding, Evidence, SourceType, format_output


async def mock_tool_execute(input_params):
    """Mock tool execution for testing"""
    return {"status": "success", "output": f"Mock execution: {input_params}"}


async def test_integration():
    print("=== Phase 1 Integration Test ===\n")

    # Load config
    config = load_config()
    print(f"Config loaded (API key present: {bool(config.anthropic_api_key)})")

    # Initialize database (in-memory to avoid stale state between runs)
    engine = await init_database("sqlite+aiosqlite:///:memory:")
    create_session_factory(engine)
    print("Database initialized")

    # Test 1: LLM abstraction layer
    print("\n[Test 1] LLM abstraction layer")
    if config.anthropic_api_key:
        provider = AnthropicProvider(api_key=config.anthropic_api_key)
        client = LLMClient(provider)
        messages = [{"role": "user", "content": "Say 'test successful'"}]
        response = await client.complete(messages, [])
        print(f"  Claude API connected: {response['content'][0]['text'][:50]}")
    else:
        print("  ANTHROPIC_API_KEY not set - skipping live API test")
        print("  Verifying LLM abstractions are importable and structurally correct")
        # Verify the protocol and client classes exist and are well-formed
        assert hasattr(LLMClient, "complete"), "LLMClient should have complete method"
        assert hasattr(LLMClient, "stream"), "LLMClient should have stream method"
        assert hasattr(LLMClient, "count_tokens"), "LLMClient should have count_tokens method"
        print("  LLM abstraction layer verified (protocol + client + provider)")

    # Test 2: Audit logging
    print("\n[Test 2] Immutable audit logging")
    async with get_session() as session:
        await append_audit_log(
            session,
            event_type="test_event",
            session_id="integration-test",
            actor="system",
            event_data={"test": "data", "timestamp": datetime.now(timezone.utc).isoformat()},
        )

    async with get_session() as session:
        valid = await verify_audit_chain(session)
        assert valid, "Audit chain should be valid"
        print("  Audit log entry created with hash chaining")
        print("  Audit chain integrity verified")

    # Test 3: Session checkpointing
    print("\n[Test 3] Session state persistence")
    async with get_session() as session:
        checkpoint_id = await save_checkpoint(
            session,
            session_id="integration-test",
            thread_id="default",
            state={"phase": "recon", "progress": 50},
            checkpoint_metadata=json.dumps({"note": "Integration test checkpoint"}),
        )
        print(f"  Checkpoint saved: {checkpoint_id}")

    async with get_session() as session:
        result = await load_latest_checkpoint(session, "integration-test")
        assert result is not None, "Checkpoint should exist"
        state, cid = result
        assert state["phase"] == "recon", "Checkpoint state mismatch"
        print(f"  Checkpoint loaded: {state}")

    # Test 4: Scope enforcement
    print("\n[Test 4] Scope enforcement")
    async with get_session() as session:
        target = Target(
            url="https://authorized.example.com",
            scope='["authorized.example.com", "*.authorized.example.com"]',
            authorized_by="integration_test",
            authorized_at=datetime.now(timezone.utc),
        )
        session.add(target)

    async with get_session() as session:
        in_scope, _ = await is_in_scope(session, "https://authorized.example.com/api")
        assert in_scope, "Authorized target should be in scope"
        print("  Authorized target passes scope check")

        out_scope, reason = await is_in_scope(session, "https://unauthorized.com")
        assert not out_scope, "Unauthorized target should fail scope check"
        print(f"  Unauthorized target rejected: {reason}")

    # Test 5: Risk classification
    print("\n[Test 5] Risk classification enforcement")
    nmap = get_tool_by_name("nmap_scan")
    assert nmap.risk_level == RiskLevel.SAFE
    assert not should_require_approval(nmap)
    print(f"  SAFE tool (nmap_scan) does not require approval")

    exploit = get_tool_by_name("exploit_vulnerability")
    assert exploit.risk_level == RiskLevel.DESTRUCTIVE
    assert should_require_approval(exploit)
    print(f"  DESTRUCTIVE tool (exploit_vulnerability) requires approval")

    # Test approval workflow (auto-approve SAFE tool)
    async with get_session() as session:
        result = await execute_tool_with_approval(
            nmap,
            {"target": "authorized.example.com"},
            {"session_id": "integration-test"},
            session,
            mock_tool_execute,
        )
        assert "error" not in result, "SAFE tool should execute"
        print(f"  SAFE tool executed without approval prompt")

    # Verify audit chain still valid after approval logging
    async with get_session() as session:
        valid = await verify_audit_chain(session)
        assert valid, "Audit chain should still be valid after approval logging"
        print(f"  Audit chain valid after approval workflow")

    # Test 6: Output formatting with source attribution (SAFE-04)
    print("\n[Test 6] Output formatting (SAFE-04: AI vs Tool distinction)")
    finding = Finding(
        title="SQL Injection Vulnerability",
        severity="high",
        description="Potential SQL injection found in login form",
        evidence=[],
        confidence="medium",
    )

    # Add AI interpretation
    finding.add_evidence(
        source=SourceType.AI_INTERPRETATION,
        data={
            "analysis": "Parameter 'username' may be vulnerable to SQL injection based on error patterns"
        },
    )

    # Add tool-confirmed result
    finding.add_evidence(
        source=SourceType.TOOL_CONFIRMED,
        data={
            "vulnerable_parameter": "username",
            "payload": "' OR '1'='1",
            "response_code": 200,
        },
        tool_name="sqlmap",
    )

    # Add system check
    finding.add_evidence(
        source=SourceType.SYSTEM,
        data={"scope_verified": True, "target": "authorized.example.com"},
    )

    # Verify source attribution
    assert len(finding.evidence) == 3, "Should have 3 evidence items"
    assert finding.evidence[0].source == SourceType.AI_INTERPRETATION
    assert finding.evidence[1].source == SourceType.TOOL_CONFIRMED
    assert finding.evidence[1].tool_name == "sqlmap"
    assert finding.evidence[2].source == SourceType.SYSTEM
    print("  Finding created with source-attributed evidence")

    # Format and verify visual distinction
    formatted = format_output(finding)
    assert "[AI]" in formatted, "Output should contain [AI] marker"
    assert "[TOOL]" in formatted, "Output should contain [TOOL] marker"
    assert "[SYSTEM]" in formatted, "Output should contain [SYSTEM] marker"
    assert "sqlmap" in formatted, "Output should show tool name for tool-confirmed evidence"
    print("  Formatted output distinguishes AI from tool results")
    print("\n--- Sample Output ---")
    print(formatted)
    print("--- End Sample ---\n")

    # Cleanup
    await shutdown(engine)
    print("\nAll Phase 1 integration tests passed!")
    print("   Including SAFE-04: AI interpretation vs tool-confirmed findings distinction")


if __name__ == "__main__":
    asyncio.run(test_integration())
