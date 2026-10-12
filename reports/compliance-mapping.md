# Compliance mapping — CP5

| Nguồn / chủ đề | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| [Luật 91/2025/QH15 — Luật Bảo vệ dữ liệu cá nhân](https://vanban.chinhphu.vn/?classid=1&docid=214590&pageid=27160) | Phát hiện/redact bốn loại PII và deny egress cho dữ liệu `restricted`. | `agent/pii.py:54`, `agent/pii.py:72`, `agent/policy.py:82`, `agent/runner.py:178` | Đã đối chiếu nguồn chính thức để xác nhận tên/số văn bản, nhưng **chưa xác minh điều khoản cụ thể**. Regex và mock lab không chứng minh tuân thủ pháp luật. |
| [NĐ 356/2025/NĐ-CP](https://vanban.chinhphu.vn/?classid=1&docid=216387&pageid=27160) | OBO kiểm principal, purpose, TTL và giao scope trước tool riêng tư. | `agent/policy.py:92`, `agent/policy.py:102`, `agent/runner.py:190` | **Chưa xác minh điều khoản cụ thể**; `principals.json` chỉ là fixture, không phải xác thực production. |
| [Luật 134/2025/QH15 — Luật Trí tuệ nhân tạo](https://vanban.chinhphu.vn/?classid=1&docid=216334&orggroupid=1&pageid=27160) | Tách run dữ liệu không tin cậy/private store, ghi audit hash-chain để có bằng chứng quyết định. | `agent/runner.py:125`, `agent/runner.py:156`, `agent/ledger.py:55`, `agent/ledger.py:75` | **Chưa xác minh điều khoản cụ thể**; ledger không chống cắt đuôi hoặc viết lại toàn bộ file khi không có mốc tin cậy ngoài file. |
| [OWASP ASI01, ASI03, ASI04](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) | ASI01: ticket untrusted không quyết định customer; ASI03: scope/OBO; ASI04: lock hash, Gitleaks và hook pin. | `agent/runner.py:168`, `agent/policy.py:102`, `.pre-commit-config.yaml:1`, `requirements.lock:1`, `reports/secrets-incident.md:1` | Mapping kỹ thuật là tham chiếu rủi ro, không phải chứng nhận hoặc đánh giá độc lập. |

Chỉ ghi điều khoản cụ thể khi đã đối chiếu văn bản gốc. Mô phỏng kỹ thuật không tự chứng minh tuân thủ pháp luật.
