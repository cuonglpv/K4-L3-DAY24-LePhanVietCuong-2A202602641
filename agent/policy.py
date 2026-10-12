"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


_VALID_CLASSIFICATIONS = {"public", "internal", "restricted"}
_PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"


def _principals() -> dict:
    """Load the trusted lab fixture; it is not a production identity system."""
    try:
        return json.loads(_PRINCIPALS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _expired(expires_at: str) -> bool:
    """A missing, malformed, naive, or elapsed timestamp is fail-closed."""
    if not expires_at:
        return True
    try:
        instant = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return True
    if instant.tzinfo is None:
        return True
    return instant.astimezone(timezone.utc) <= datetime.now(timezone.utc)


def check(context: PolicyContext) -> tuple[bool, str]:
    """Decide a tool request from classification and effective OBO scope."""
    if context.data_classification not in _VALID_CLASSIFICATIONS:
        return False, "unknown data classification"

    # This rule is independent of a caller's role: no restricted data goes to
    # an egress-enabled run.
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "restricted data cannot enter an egress-enabled run"

    principal = _principals().get(context.principal_id)
    if principal is None:
        return False, "unknown principal"
    if not context.requested_tool:
        return False, "requested tool is required"
    if context.request_purpose not in set(principal.get("purposes", [])):
        return False, "purpose is not authorized for this principal"
    if _expired(context.expires_at):
        return False, "delegation grant is missing, invalid, or expired"

    effective_tools = set(principal.get("allowed_tools", [])) & set(context.agent_scopes)
    if context.delegation_depth > 0:
        effective_tools &= set(context.parent_scopes)
    if context.requested_tool not in effective_tools:
        return False, "requested tool is outside the effective OBO scope"

    return True, "principal, purpose, TTL, and effective scope are authorized"
