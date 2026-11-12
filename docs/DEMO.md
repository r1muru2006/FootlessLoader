# Demo/video storyboard

Mục tiêu: quay một video ngắn chứng minh PoC chạy trong VM và detector phản
ứng độc lập. Không cần dựng; quay màn hình liên tục, có timestamp.

## Chuẩn bị

- VM đã snapshot, Sysmon đã bật (nếu quay telemetry).
- Cửa sổ 1: target; cửa sổ 2: loader; cửa sổ 3: detector.
- Đã build và copy `dist/` vào `C:\Footless\bin`.

## Cảnh 1 — Baseline benign (B01/B02)

1. Chạy target, quay `READY ... PID/TID`.
2. Không chạy loader; chờ target `DONE`.
3. Mở `marker.jsonl` (rỗng hoặc chỉ self-DLL) và chạy detector trên
   `loader.jsonl`/telemetry: `clean`.
4. Nói rõ: không có cross-process chain.

## Cảnh 2 — CRT/NT (P01/P02)

1. Chạy target, ghi PID/TID.
2. Chạy loader `--method crt` (rồi `nt`), quay output `[PASS]`.
3. Mở `marker.jsonl`: PID = target, TID = `new_tid`.
4. Chạy detector: `alert`, hiện `access`, `remote_thread`, `process_graph`.
5. So sánh hai lần: cùng kết quả, khác API name.

## Cảnh 3 — Stub/section (P03/P05)

1. Target mới; loader `--method stub` (rồi `section`).
2. Quay `memory_allocate`, `memory_write`, `memory_protect` RW→RX,
   `remote_thread`.
3. Detector: `rx_anomaly`, `injection_behavior`, score cao hơn CRT.
4. Nói rõ section là pagefile-backed, không private allocation.

## Cảnh 4 — APC (P04)

1. Target ở chế độ alertable; loader `--method apc --tid <TID>`.
2. Quay `apc_queue`; marker có thể xuất hiện trên TID có sẵn.
3. Detector: alert dù không có remote thread, nhờ memory + graph + access.

## Cảnh 5 — Quiet variant (P06)

1. Chạy `footless_loader_quiet.exe` (cùng method stub).
2. Chỉ ra log không còn tên API.
3. Detector vẫn alert — chứng minh không phụ thuộc chuỗi.

## Cảnh 6 — Detector metrics (không cần VM)

1. Mở terminal: `python evaluate.py`, `python tools/ablation.py`.
2. Quay bảng P/R/F1/FPR và ablation.
3. Nói rõ telemetry là synthetic replay; cách thay bằng capture thật.

## Checklist sau quay

- [ ] Video có READY, loader process khác, marker PID/TID, detector alert.
- [ ] Không cắt ghép PID/TID.
- [ ] Lưu video + log cùng thư mục evidence.
- [ ] Ghi rõ run lỗi nếu có.
