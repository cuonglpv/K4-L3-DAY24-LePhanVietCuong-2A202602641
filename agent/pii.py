"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w-])"
)
_PHONE_RE = re.compile(r"(?<!\d)0(?:[ .-]?\d){9,10}(?!\d)")
_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_BANK_RE = re.compile(
    r"(?i)\b(?:stk|số\s*tài\s*khoản|tai\s*khoan)\b\s*[:#-]?\s*"
    r"(\d(?:[ .-]?\d){7,15})"
)


def _add_non_overlapping(matches: list[dict], entity_type: str, start: int, end: int) -> None:
    """Keep the context-aware match when recognizers overlap."""
    if any(start < entity["end"] and entity["start"] < end for entity in matches):
        return
    matches.append({"type": entity_type, "start": start, "end": end})


def detect(text: str) -> list[dict]:
    """Find supported PII without changing offsets in the input text."""
    matches: list[dict] = []

    # An explicit STK label makes an account match more specific than a
    # generic twelve-digit CCCD or a phone-like sequence.
    for match in _BANK_RE.finditer(text):
        _add_non_overlapping(matches, "VN_BANK_ACCOUNT", match.start(1), match.end(1))
    for match in _EMAIL_RE.finditer(text):
        _add_non_overlapping(matches, "EMAIL", match.start(), match.end())
    for match in _CCCD_RE.finditer(text):
        _add_non_overlapping(matches, "VN_CCCD", match.start(), match.end())
    for match in _PHONE_RE.finditer(text):
        _add_non_overlapping(matches, "VN_PHONE", match.start(), match.end())

    return sorted(matches, key=lambda entity: (entity["start"], entity["end"]))


def redact(text: str) -> str:
    # Work right-to-left so stored spans remain offsets into the original text.
    for entity in sorted(detect(text), key=lambda entity: entity["start"], reverse=True):
        text = (
            text[: entity["start"]]
            + f"[REDACTED_{entity['type']}]"
            + text[entity["end"] :]
        )
    return text
