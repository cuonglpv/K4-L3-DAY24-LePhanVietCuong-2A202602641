# Baseline — checkpoint 1

1. Chưa. Mỗi lần chạy baseline không có `agent_id`, `run_id` hay danh tính để
   kiểm quyền. `_naive_loop()` ở `agent/loop.py:27-54` chỉ nhận câu hỏi và
   LLM; dù CLI có `principal_id` ở dòng 90-91, hàm này không dùng. Vì vậy nội
   dung trong ticket cũng bị `llm.find_injection()` ở dòng 31-35 hiểu như lệnh.

2. Chưa có policy nào đứng trước lúc gửi. Nếu tìm thấy chỉ thị và đã lấy được
   hồ sơ, `_naive_loop()` tự gọi `tools.http_post()` ở
   `agent/loop.py:42-44`. `agent/tools.py:76-84` chỉ khóa URL về localhost,
   chứ không kiểm ai đang gửi hoặc dữ liệu có nhạy cảm không.

3. Dữ liệu được gom vào `{"records": collected}` ở `agent/loop.py:44`, sau
   khi `tools.read_customer()` trả hồ sơ ở dòng 37-40. Sink ghi POST vào
   `reports/sink.log`; em đã chép lại thành `reports/attack-before.log`.
   Log có dữ liệu giả của `KH-000999`.
