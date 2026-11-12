# Thu bằng chứng — ground truth vs telemetry

Mục tiêu: tách rõ **bằng chứng PoC đã chạy** khỏi **dữ liệu detector dùng**,
và chỉ ra cách thay dataset tổng hợp bằng capture thật.

## 1. Hai loại log

| File | Ai ghi | Dùng cho | Detector được đọc? |
|---|---|---|---|
| `loader.jsonl` | loader và target helper | telemetry runtime | **có** |
| `marker.jsonl` | marker DLL trong target | ground truth PID/TID/image | **không** |
| `telemetry.jsonl` | Sysmon collector | telemetry độc lập | **có** |
| `results.csv` | runner | kết luận từng run | không (evaluation) |
| `run.json` | runner | cửa sổ thời gian, PID, exit code | không |
| `environment.json` | runner | OS/snapshot/sensor | không |

Quy tắc: detector không đọc `marker.jsonl`, `injector.jsonl`, `run.json`, hay
bất kỳ file nào do chính PoC tự kết luận. Việc ghép nhãn/theo run chỉ xảy ra
trong evaluator sau khi rule đã chạy.

## 2. Schema

### `loader.jsonl`

```json
{
  "utc": "2026-11-13T01:00:00.002Z",
  "tick_ms": 102,
  "run_id": "P03",
  "scenario_id": "stub",
  "pid": 4210,
  "tid": 4211,
  "event": "memory_protect",
  "operation": "protect_memory",
  "base_address": "0x1f1000",
  "size": 24,
  "memory_protection": "RX",
  "ntstatus": "0x00000000"
}
```

Các `event`:

| event | Ý nghĩa |
|---|---|
| `source_target` | loader → target, method, image, access mask |
| `process_open` | `NtOpenProcess` + requested access |
| `memory_allocate` | cấp phát remote, protection |
| `memory_write` | ghi remote, bytes |
| `memory_protect` | RW→RX (hoặc protection khác) |
| `memory_map` | map section, backing |
| `remote_thread` | thread mới, `new_tid`, `start_address` |
| `apc_queue` | queue APC, `target_tid`, callback |
| `thread_wait` / `thread_exit` | kết quả chờ thread |
| `error` | stage + NTSTATUS/Win32 error |
| `result` | exit code tổng |

### `marker.jsonl`

```json
{
  "utc": "2026-11-13T01:00:00.010Z",
  "tick_ms": 110,
  "run_id": "P03",
  "scenario_id": "stub",
  "pid": 3312,
  "tid": 3314,
  "image": "C:\\Footless\\bin\\footless_target.exe",
  "event": "marker",
  "kind": "dll_attach"
}
```

`pid` phải bằng PID target. `tid` phải bằng `new_tid` (CRT/NT/stub/section)
hoặc TID có sẵn (APC). `kind` phân biệt `dll_attach` và `export_call`.

### `telemetry.jsonl` (Sysmon)

Collector giữ `event_id`, `record_id`, `utc`, `provider`, `data` (EventData
gốc). Detector map EID 8 → `create_remote_thread`, EID 10 → `open_process`,
EID 7 → `image_load`, EID 25 → `process_tampering`.

## 3. Ảnh/video tối thiểu

Cho mỗi method (crt/nt/stub/apc/section):

1. Target `READY` với Run ID/PID/TID.
2. Loader chạy ở PID khác, in method/target.
3. `marker.jsonl` có PID target và TID đúng (new thread hoặc existing).
4. Detector alert trên `loader.jsonl`/`telemetry.jsonl`.
5. Kết thúc: exit code, cleanup hoặc lý do deferred.

Đặt tên: `P03-<run>-target.png`, `P03-<run>-loader.png`,
`P03-<run>-marker.png`, `P03-<run>-detector.png`.

Không chỉnh sửa PID/TID/nội dung log trong ảnh. Không dùng ảnh build làm
bằng chứng injection.

## 4. Trạng thái bằng chứng trong repo

| Hạng mục | Trạng thái | Ghi chú |
|---|---|---|
| Source loader + target + marker | có | build x64 bằng MinGW-w64 13.2 |
| Build log + SHA256 | có | `dist/build.log`, `dist/sha256.txt` |
| Kiểm tra resolver/PE trên host | có | detector parse PE, static features |
| Telemetry tổng hợp theo schema | có | `../Footless-detector/datasets/telemetry/` |
| Kết quả detector trên PE thật | có | `../Footless-detector/reports/evaluation.json` |
| Chạy VM thật + marker thật | **chưa có trong repo** | cần chạy runbook; thay dataset bằng capture |
| Ảnh/video | **chưa có** | cần quay trong VM |
| Sysmon EVTX thật | **chưa có** | collector đã có, cần chạy trong VM |

Đây là điểm cần hoàn thiện trước khi nộp nếu giảng viên yêu cầu bằng chứng
VM. Repo không giả mạo log thật; các file trong `datasets/telemetry` được
đánh dấu rõ là **synthetic replay** trong generator.

## 5. Thay synthetic bằng capture thật

1. Chạy `scripts/run_lab.ps1` cho từng scenario.
2. Copy `loader.jsonl` (và `telemetry.jsonl` nếu có) từ run dir.
3. Tạo manifest CSV:

```csv
scenario_id,label,format,path,technique,expected_marker,controlled_change
VM-P01,malicious,jsonl,evidence/20261113T.../P01/loader.jsonl,crt,yes,CreateRemoteThread
```

4. Chạy `python evaluate.py --manifest datasets/my_vm_manifest.csv`.
5. Lưu `reports/evaluation.json` + ảnh/video + EVTX.
6. Ghi rõ run lỗi/không đánh giá; không biến chúng thành true negative.

## 6. Checklist trước khi nộp

- [ ] `README.md` (loader + detector + root) khớp với binary đã build.
- [ ] `dist/sha256.txt` khớp binary trong `datasets/pe/`.
- [ ] `python -m unittest discover` pass.
- [ ] `python evaluate.py` chạy lại được và khớp `reports/evaluation.md`.
- [ ] `python tools/ablation.py` chạy lại được.
- [ ] `datasets/pe/SHA256.txt` khớp file.
- [ ] Không có log/ảnh giả mạo; synthetic được ghi nhãn.
- [ ] Safety checklist trong `../../SAFETY.md` đã đọc.
