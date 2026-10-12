# Verification

## CP3a — PII gate

- Lệnh: `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`
- Kết quả: `gold=118`, `pred=118`, `tp=118`; precision `1.000`, recall
  `1.000` (Python 3.12.10).
- Giới hạn: recognizer regex chỉ nhận diện bốn định dạng trong lab. Nó không
  xác nhận danh tính, không hiểu ngữ cảnh tự do, và có thể bỏ sót/nhầm những
  cách viết mới ngoài định dạng CCCD, phone, STK và email đã định nghĩa.

## Kiểm tra cuối trước khi nộp

- OS / Python / Gitleaks version: sẽ cập nhật ở CP4–CP5.
- `python -m pytest tests/ -q`: sẽ chạy ở CP5.
- `pre-commit run --all-files`: sẽ chạy ở CP4–CP5.
- Ledger verify: sẽ chạy ở CP3e–CP5.
- Các lỗi còn lại: Gitleaks chưa có trong PATH tại thời điểm CP1; cần cài đúng
  v8.30.1 trước khi hoàn tất CP4.
