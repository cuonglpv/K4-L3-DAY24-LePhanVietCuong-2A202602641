# Baseline — checkpoint 1

1. Baseline chưa tạo `agent_id`, `run_id` hay danh tính người dùng để kiểm
   quyền cho mỗi lần chạy. `agent/loop.py:27-54` chỉ nhận `message` và `llm`;
   lời gọi từ CLI ở `agent/loop.py:90-91` có truyền `principal_id` nhưng
   `_naive_loop()` không nhận hoặc dùng giá trị đó. Ticket là dữ liệu không tin
   cậy, nhưng nội dung trong `combined_text` vẫn được đưa cho
   `llm.find_injection()` tại `agent/loop.py:31-35` như một chỉ thị có thể thi
   hành.

2. Không có policy kiểm mục đích, quyền hay phân loại dữ liệu trước egress.
   Khi `find_injection()` trả instruction và có record thu được,
   `_naive_loop()` tự quyết định gọi `tools.http_post()` ở
   `agent/loop.py:42-44`; `agent/tools.py:76-84` chỉ giới hạn URL ở localhost,
   không kiểm ai được gửi hay body có dữ liệu restricted hay không.

3. Body POST được tạo trực tiếp tại `agent/loop.py:44` với
   `{"records": collected}`, sau `tools.read_customer()` đã trả hồ sơ ở
   `agent/loop.py:37-40`. Sink nhận body qua HTTP và ghi evidence vào
   `reports/sink.log` (sau đó được sao chép thành `reports/attack-before.log`);
   file log có các giá trị synthetic của `KH-000999`.
