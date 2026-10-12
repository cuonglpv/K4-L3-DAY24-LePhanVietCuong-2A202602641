"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _hash_args(args: dict) -> str:
    encoded = json.dumps(args, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _append_audit(entry: dict, path: Path) -> None:
    """Temporary CP3c JSONL audit; CP3e upgrades it to a hash chain."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")


def _authorize(
    *, ledger_path: Path, run_id: str, agent_id: str, principal_id: str,
    expires_at: str, tool: str, args: dict, classification: str,
    purpose: str, egress_enabled: bool, agent_scopes: tuple[str, ...],
    parent_scopes: tuple[str, ...] = (), delegation_depth: int = 0,
) -> bool:
    allowed, reason = check(PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=agent_id,
        delegation_depth=delegation_depth,
        egress_enabled=egress_enabled,
        principal_id=principal_id,
        requested_tool=tool,
        agent_scopes=agent_scopes,
        parent_scopes=parent_scopes,
        expires_at=expires_at,
    ))
    _append_audit({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "run_id": run_id,
        "tool": tool,
        "args_hash": _hash_args(args),
        "classification": classification,
        "decision": "allow" if allowed else "deny",
        "reason": reason,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
    }, ledger_path)
    return allowed


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    """Run tool calls on behalf of a simulated principal with PEP checks."""
    ledger_path = (log_dir / "ledger.jsonl") if log_dir is not None else DEFAULT_LEDGER_PATH
    run_id = uuid.uuid4().hex
    agent_id = "lab24-agent/obo-run"
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    scopes = ("search_docs", "read_customer")

    docs: list[dict] = []
    if _authorize(
        ledger_path=ledger_path, run_id=run_id, agent_id=agent_id,
        principal_id=principal_id, expires_at=expires_at, tool="search_docs",
        args={"query": message}, classification="internal",
        purpose="summarize-tickets", egress_enabled=False, agent_scopes=scopes,
    ):
        docs = tools.search_docs(message)

    combined_text = "\n\n".join(str(doc.get("text", "")) for doc in docs)
    injected = llm.find_injection(combined_text)
    records: list[dict] = []
    if injected is not None:
        for customer_id in injected.customer_ids:
            if _authorize(
                ledger_path=ledger_path, run_id=run_id, agent_id=agent_id,
                principal_id=principal_id, expires_at=expires_at, tool="read_customer",
                args={"customer_id": customer_id}, classification="restricted",
                purpose="support-reply", egress_enabled=False, agent_scopes=scopes,
            ):
                try:
                    records.append(tools.read_customer(customer_id))
                except tools.ToolError:
                    pass

        # Log the attempted egress before it could execute.  Policy's
        # restricted+egress rule denies it for every principal.
        if _authorize(
            ledger_path=ledger_path, run_id=run_id, agent_id=agent_id,
            principal_id=principal_id, expires_at=expires_at, tool="http_post",
            args={"target_url": injected.target_url, "record_count": len(records)},
            classification="restricted", purpose="support-reply", egress_enabled=True,
            agent_scopes=scopes,
        ):
            tools.http_post(injected.target_url, {"records": records})

    return llm.summarize(docs)
