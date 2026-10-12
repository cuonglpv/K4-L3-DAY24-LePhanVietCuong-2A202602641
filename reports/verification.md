# Verification

## CP3a — PII gate

- Lệnh: `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`
- Kết quả: `gold=118`, `pred=118`, `tp=118`; precision `1.000`, recall
  `1.000` (Python 3.12.10).
- Giới hạn: recognizer regex chỉ nhận diện bốn định dạng trong lab. Nó không
  xác nhận danh tính, không hiểu ngữ cảnh tự do, và có thể bỏ sót/nhầm những
  cách viết mới ngoài định dạng CCCD, phone, STK và email đã định nghĩa.

## Các checkpoint khác

- CP1: đọc `agent/loop.py`, cập nhật `reports/baseline.md`.
- CP2: `python -m agent.check_lure corpus/ticket-90*.md` báo 4/4 lure sẵn
  sàng; replay baseline tạo 4 dòng synthetic trong `attack-before.log`.
- CP3b: `python -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp` —
  4 passed.
- CP3c: `python -m pytest tests/test_obo.py -v --basetemp=.pytest_tmp` —
  5 passed.
- CP3d: `python -m pytest tests/test_split.py tests/test_injection.py -v
  --basetemp=.pytest_tmp` — 9 passed.
- CP3e: `python -m pytest tests/test_ledger.py -v --basetemp=.pytest_tmp` —
  3 passed; `verify(Path('reports/ledger.jsonl'))` trả `True`.
- CP4: Gitleaks `8.30.1`; history có đúng 1 finding synthetic tại `1bdd849`
  (exit `1` dự kiến), current tree sạch (exit `0`). `pip install
  --require-hashes -r requirements.lock`, `pre-commit run --all-files`, và
  `python -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp`
  đều pass (3 test).

## Kiểm tra cuối CP5

- Môi trường: Windows; Python 3.12.10; Gitleaks 8.30.1 trong PATH.
- Lệnh: `python -m pytest tests/ -q --basetemp=.pytest_tmp` — **33 passed,
  0 skipped**.
- Replay DPO: `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn
  mở tuần này"`; `attack-after.log` có **0 byte**.
- `verify(Path('reports/ledger.jsonl'))` trả `True`; ledger có deny
  `http_post`, reason không rỗng và `on_behalf_of=dpo`.
- Sự cố đã xử lý: terminal Windows ban đầu dùng CP1252 làm CLI in tiếng Việt
  lỗi; đặt `PYTHONIOENCODING=utf-8`. Gitleaks ban đầu chưa có trong PATH;
  đã cài v8.30.1 từ release chính thức và hook pass. Không còn lỗi chặn nộp
  nào được biết tại thời điểm kiểm cuối.
