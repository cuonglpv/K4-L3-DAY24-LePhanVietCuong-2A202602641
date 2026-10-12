# DPIA-lite — CP5

1. **Dữ liệu:** Ticket là phần không đáng tin. Hồ sơ khách giả có CCCD, số
   điện thoại, STK và email nên được xem là `restricted`. Bài không dùng PII
   hoặc token thật.
2. **Ai làm gì:** `support_l1` chỉ được tóm tắt ticket. `dpo` được đọc hồ sơ
   liên quan để trả lời hỗ trợ. `--as` chỉ chọn quyền giả lập, không phải đăng
   nhập thật.
3. **Dữ liệu đi qua đâu:** Run A dùng `search_docs`. Sang Run B chỉ có số
   ticket từ tên file. Run B tra `related_tickets` rồi mới được gọi
   `read_customer` nếu policy cho phép. Sink chỉ là localhost và replay CP5
   không gửi gì tới đó. Ledger chỉ giữ hash tham số, decision và reason.
4. **Kết quả và giới hạn:** `attack-before.log` có 4 POST dữ liệu giả,
   `attack-after.log` là 0 byte. Ledger có lệnh `http_post` bị deny cho `dpo`
   và `verify()` trả `True`. Đây vẫn là mock; regex có thể bỏ sót định dạng lạ,
   quyền là fixture, và hash chain không phát hiện cắt dòng cuối nếu không có
   nơi lưu mốc tin cậy khác.
