# Verification

## CP3a — PII gate

- Lệnh: `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`
- Kết quả: `gold=118`, `pred=118`, `tp=118`; precision `1.000`, recall
  `1.000` (Python 3.12.10).
- Giới hạn: regex chỉ nhận 4 kiểu trong bài. Nếu số được viết lạ đi hoặc câu
  quá khác mẫu, nó vẫn có thể bỏ sót hay nhận nhầm.

## Các checkpoint khác

- CP1: em đọc `agent/loop.py` và ghi lại lỗi ở `reports/baseline.md`.
- CP2: `python -m agent.check_lure corpus/ticket-90*.md` báo 4/4 lure dùng
  được; chạy baseline tạo 4 dòng dữ liệu giả trong `attack-before.log`.
- CP3b: `python -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp` —
  4 passed.
- CP3c: `python -m pytest tests/test_obo.py -v --basetemp=.pytest_tmp` —
  5 passed.
- CP3d: `python -m pytest tests/test_split.py tests/test_injection.py -v
  --basetemp=.pytest_tmp` — 9 passed.
- CP3e: `python -m pytest tests/test_ledger.py -v --basetemp=.pytest_tmp` —
  3 passed; `verify(Path('reports/ledger.jsonl'))` trả `True`.
- CP4: Gitleaks `8.30.1` tìm đúng 1 token demo trong commit `1bdd849` (mã 1
  là như dự kiến); file hiện tại sạch (mã 0). Cài từ lockfile, hook và 3 test
  supply-chain đều pass.

## Kiểm tra cuối CP5

- Môi trường: Windows; Python 3.12.10; Gitleaks 8.30.1 trong PATH.
- Lệnh: `python -m pytest tests/ -q --basetemp=.pytest_tmp` — **33 passed,
  0 skipped**.
- Chạy lại bằng DPO: `attack-after.log` có **0 byte**.
- `verify(Path('reports/ledger.jsonl'))` trả `True`. Ledger có dòng chặn
  `http_post`, có reason và ghi đúng `on_behalf_of=dpo`.
- Lúc đầu terminal Windows không in được tiếng Việt vì CP1252; em đặt
  `PYTHONIOENCODING=utf-8` để sửa. Gitleaks lúc đầu chưa có PATH, sau đó đã
  cài bản 8.30.1 và hook chạy pass. Hiện chưa còn lỗi nào cản việc nộp bài.
