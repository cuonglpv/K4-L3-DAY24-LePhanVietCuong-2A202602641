# Compliance mapping — CP5

| Nguồn / chủ đề | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| [Luật 91/2025/QH15 — Luật Bảo vệ dữ liệu cá nhân](https://vanban.chinhphu.vn/?classid=1&docid=214590&pageid=27160) | Em nhận diện/che 4 loại PII và không cho dữ liệu `restricted` đi ra ngoài. | `agent/pii.py:54`, `agent/pii.py:72`, `agent/policy.py:82`, `agent/runner.py:178` | Em mới kiểm tên và số văn bản trên nguồn chính thức, **chưa kiểm từng điều khoản**. Regex và mock không có nghĩa là hệ thống đã tuân thủ luật. |
| [NĐ 356/2025/NĐ-CP](https://vanban.chinhphu.vn/?classid=1&docid=216387&pageid=27160) | Trước mỗi tool, code kiểm ai gọi, gọi để làm gì, còn hạn không và có đúng scope không. | `agent/policy.py:92`, `agent/policy.py:102`, `agent/runner.py:190` | **Chưa kiểm từng điều khoản**. `principals.json` chỉ là dữ liệu giả cho bài lab, không phải đăng nhập thật. |
| [Luật 134/2025/QH15 — Luật Trí tuệ nhân tạo](https://vanban.chinhphu.vn/?classid=1&docid=216334&orggroupid=1&pageid=27160) | Em tách phần đọc ticket và phần đọc hồ sơ; ledger lưu lại quyết định cho phép/chặn. | `agent/runner.py:125`, `agent/runner.py:156`, `agent/ledger.py:55`, `agent/ledger.py:75` | **Chưa kiểm từng điều khoản**. Ledger không phát hiện được việc ai đó xóa dòng cuối hoặc viết lại cả file khi không có nơi giữ mốc tin cậy khác. |
| [OWASP ASI01, ASI03, ASI04](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) | Ticket xấu không tự chọn được khách để đọc; quyền được giới hạn theo scope; dependency có lock, Gitleaks và hook kiểm tra. | `agent/runner.py:168`, `agent/policy.py:102`, `.pre-commit-config.yaml:1`, `requirements.lock:1`, `reports/secrets-incident.md:1` | Đây là cách đối chiếu rủi ro để học, không phải chứng nhận bảo mật hay tuân thủ. |

Chỉ ghi điều khoản cụ thể khi đã đối chiếu văn bản gốc. Mô phỏng kỹ thuật không tự chứng minh tuân thủ pháp luật.
