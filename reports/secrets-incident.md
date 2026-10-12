# Báo cáo CP4 — token synthetic trong lịch sử Git

- **Tool đã dùng:** Gitleaks `8.30.1` từ release chính thức.
- **Chỗ phát hiện token giả:** commit
  `1bdd849922156c868a5ee9293d68f5b72e242d2c` (`1bdd849`).
- **Quét lịch sử:** lệnh `gitleaks git --config .gitleaks.toml --redact
  --verbose .` trả mã `1`. Đây là kết quả đúng vì tool tìm thấy một chuỗi đã
  che nội dung ở `lab-fake-secret.txt`, dòng 1, rule
  `lab24-synthetic-token`. Chuỗi này là token demo của bài lab, không dùng
  được ở đâu cả.
- **Quét file hiện tại:** lệnh `gitleaks dir --config .gitleaks.toml --redact
  .` trả mã `0`, tức là không có finding. Không phải thêm allowlist.
- **Dependency và hook:** `requirements.lock` có version và hash;
  `pip install --require-hashes -r requirements.lock` chạy được. Hook
  `gitleaks-system` được pin ở `v8.30.1`; `pre-commit run --all-files` pass.
- **Nếu đây là token thật:** cần thu hồi/rotate ngay ở nơi cấp token, kiểm tra
  nó đã bị dùng sai ở đâu và thay token ở những chỗ đang dùng token cũ.
- **Điểm cần nhớ:** xoá file ở HEAD không làm token cũ tự vô hiệu. Lockfile và
  hook chỉ giúp tránh lỗi mới, không thay thế bước rotate hay xử lý sự cố.
