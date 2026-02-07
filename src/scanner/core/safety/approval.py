"""Human-in-the-loop approval workflow (SAFE-03).

Implements guided mode where SAFE tools auto-execute but MODERATE
and DESTRUCTIVE tools require explicit human approval. All approval
decisions are logged to the immutable audit trail.

Follows RESEARCH.md Pattern 7: Guided Mode with Human Approval.

Provides:
- ApprovalDecision: Enum for approve/deny/modify decisions
- request_approval: Display approval prompt and get user decision
- execute_tool_with_approval: Full workflow with auto-approve for SAFE tools
"""

import json
from enum import Enum

from sqlalchemy.ext.asyncio import AsyncSession

from scanner.core.llm.tools import RiskLevel, ToolDefinition
from scanner.core.persistence.audit import append_audit_log
from scanner.core.safety.risk import get_risk_description, should_require_approval


class ApprovalDecision(str, Enum):
    """Decision made by user for tool execution approval."""

    APPROVE = "approve"
    DENY = "deny"
    MODIFY = "modify"


async def request_approval(
    tool_name: str,
    tool_input: dict,
    risk_level: RiskLevel,
    context: dict,
) -> tuple[ApprovalDecision, dict]:
    """Request human approval for tool execution (SAFE-03).

    Displays the tool details and risk information, then prompts
    the user for a decision. In Phase 2 this will integrate with
    CLI, and in Phase 4 with Telegram.

    Args:
        tool_name: Name of tool to execute
        tool_input: Tool parameters
        risk_level: Risk classification of the tool
        context: Additional context (session_id, description, etc.)

    Returns:
        Tuple of (decision, final_input) where final_input may be
        modified parameters if user chose MODIFY
    """
    # Format approval request
    print(f"\nAPPROVAL REQUIRED - {risk_level.value.upper()}")
    print(f"Tool: {tool_name}")
    print(f"Risk: {get_risk_description(risk_level)}")
    print(f"Input: {json.dumps(tool_input, indent=2)}")
    if context:
        print(f"Context: {context.get('description', 'N/A')}")
    print("\nOptions: [A]pprove, [D]eny, [M]odify")

    # Get user input (Phase 2 will integrate with CLI, Phase 4 with Telegram)
    response = input("Decision: ").strip().upper()

    if response == "A":
        return ApprovalDecision.APPROVE, tool_input
    elif response == "D":
        return ApprovalDecision.DENY, {}
    elif response == "M":
        print("Enter modified parameters (JSON):")
        try:
            modified = json.loads(input())
            return ApprovalDecision.MODIFY, modified
        except json.JSONDecodeError:
            print("Invalid JSON, denying by default")
            return ApprovalDecision.DENY, {}
    else:
        # Default to deny for safety
        return ApprovalDecision.DENY, {}


async def execute_tool_with_approval(
    tool: ToolDefinition,
    tool_input: dict,
    context: dict,
    session: AsyncSession,
    execute_fn,
) -> dict:
    """Execute tool with risk-based approval workflow.

    Implements the full guided mode workflow:
    1. Check if tool requires approval based on risk level
    2. Auto-approve SAFE tools, prompt for MODERATE/DESTRUCTIVE
    3. Log the approval decision to immutable audit trail
    4. Execute the tool if approved
    5. Log the execution result

    Args:
        tool: Tool definition with risk level
        tool_input: Tool parameters
        context: Execution context (session_id required)
        session: Database session for audit logging
        execute_fn: Actual tool execution function (async callable)

    Returns:
        Tool execution result dict, or error dict if denied/failed
    """
    session_id = context.get("session_id", "unknown")

    # SAFE tools auto-approve
    if not should_require_approval(tool):
        decision = ApprovalDecision.APPROVE
        final_input = tool_input
    else:
        # Request approval for MODERATE/DESTRUCTIVE
        decision, final_input = await request_approval(
            tool.name,
            tool_input,
            tool.risk_level,
            context,
        )

    # Log approval decision to immutable audit trail (PERS-04)
    await append_audit_log(
        session,
        event_type="approval_decision",
        session_id=session_id,
        actor="user",
        event_data={
            "tool": tool.name,
            "risk_level": tool.risk_level.value,
            "decision": decision.value,
            "original_input": tool_input,
            "final_input": final_input,
        },
    )

    if decision == ApprovalDecision.DENY:
        return {"error": "User denied approval", "tool": tool.name}

    # Execute tool
    try:
        result = await execute_fn(final_input)

        # Log execution result
        await append_audit_log(
            session,
            event_type="tool_executed",
            session_id=session_id,
            actor="system",
            event_data={
                "tool": tool.name,
                "input": final_input,
                "success": True,
                "result_summary": str(result)[:200],  # Truncate for audit log
            },
        )

        return result
    except Exception as e:
        # Log execution failure
        await append_audit_log(
            session,
            event_type="tool_failed",
            session_id=session_id,
            actor="system",
            event_data={
                "tool": tool.name,
                "input": final_input,
                "error": str(e),
            },
        )
        return {"error": str(e), "tool": tool.name}
