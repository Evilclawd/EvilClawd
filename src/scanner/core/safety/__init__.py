"""Safety framework with scope enforcement, risk classification, and approval workflow."""

from .scope import ScopeChecker, is_in_scope
from .risk import should_require_approval, get_risk_description
from .approval import ApprovalDecision, request_approval, execute_tool_with_approval

__all__ = [
    "ScopeChecker",
    "is_in_scope",
    "should_require_approval",
    "get_risk_description",
    "ApprovalDecision",
    "request_approval",
    "execute_tool_with_approval",
]
