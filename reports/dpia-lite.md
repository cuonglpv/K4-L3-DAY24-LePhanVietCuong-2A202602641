# DPIA-lite — CP5

1. **Loại dữ liệu và phân loại:** Ticket trong `corpus/` là dữ liệu không tin
   cậy; hồ sơ customer synthetic gồm CCCD, số điện thoại, STK và email là
   `restricted`. Không sử dụng PII hay credential thật.
2. **Mục đích và principal:** `support_l1` chỉ tổng hợp ticket;
   `dpo` (fixture mô phỏng) được đọc khách liên quan cho `support-reply`.
   `--as` không phải cơ chế xác thực danh tính production.
3. **Luồng dữ liệu:** Run A dùng `search_docs`; chỉ ID số từ tên file sang
   Run B. Run B tra `related_tickets` rồi có thể gọi `read_customer` sau PEP.
   Sink thử nghiệm duy nhất là `http://127.0.0.1:10024`; replay CP5 không gọi
   nó. Ledger lưu hash tham số, decision và reason, không lưu hồ sơ thô.
4. **Bằng chứng và giới hạn:** `reports/attack-before.log` có 4 POST
   synthetic, còn `reports/attack-after.log` là 0 byte; `ledger.jsonl` có
   `http_post` deny cho `dpo` và `verify()` trả `True`. Đây là mock
   deterministic, regex có giới hạn coverage, policy/principal là fixture,
   và hash chain trong một file không phát hiện cắt đuôi hay viết lại toàn bộ
   chuỗi khi thiếu mốc tin cậy bên ngoài.
