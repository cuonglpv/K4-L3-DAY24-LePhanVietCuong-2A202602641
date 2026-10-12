# Báo cáo CP4 — token synthetic trong lịch sử Git

- **Scanner và phiên bản:** Gitleaks `8.30.1` từ release chính thức.
- **Commit chứa token giả:** `1bdd849922156c868a5ee9293d68f5b72e242d2c`
  (`1bdd849`), commit seed của bài lab.
- **Quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact --verbose .`
  trả exit code `1` như mong đợi, với một finding đã redact: file
  `lab-fake-secret.txt`, dòng 1, rule `lab24-synthetic-token`. Giá trị là
  token `LAB24-DEMO` vô hiệu do bài lab cài sẵn, không phải credential thật.
- **Quét file hiện tại:** `gitleaks dir --config .gitleaks.toml --redact .`
  trả exit code `0`, không có finding. Không cần thêm allowlist.
- **Dependency và hook:** `requirements.lock` được tạo bằng
  `pip-compile --generate-hashes`; `pip install --require-hashes -r
  requirements.lock` thành công. `.pre-commit-config.yaml` pin
  `gitleaks-system` tại `v8.30.1`, và `pre-commit run --all-files` pass.
- **Nếu đây là credential thật:** thu hồi/rotate ở dịch vụ phát hành token
  ngay lập tức, điều tra phạm vi sử dụng sai, cập nhật mọi hệ thống dùng token
  cũ và xử lý các bản sao/lịch sử công khai.
- **Giới hạn:** xoá file khỏi HEAD không thu hồi token đã lộ trong lịch sử;
  pin dependency và hook chỉ giảm nguy cơ secret/dependency mới, không thay
  thế rotate hoặc ứng phó sự cố.
