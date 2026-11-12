# Biến thể có kiểm soát và ảnh hưởng đến detector

Tài liệu này phục vụ hạng mục B (2 điểm): liệt kê biến thể, đối chứng benign,
mô tả thay đổi và ảnh hưởng đo được đến detector. Kết quả đo nằm trong
`../Footless-detector/reports/`.

## 1. Ma trận scenario

| ID | Loại | Thay đổi có kiểm soát | Marker (mong đợi) | Detector phải thấy |
|---|---|---|---|---|
| B01 | benign | target chạy một mình | không | không có cross-process evidence |
| B02 | benign | target tự `LoadLibraryW` marker DLL | có (PID target) | image load same-process; không alert |
| B03 | benign | app console thường, local memory | không | không có chain |
| B04 | benign | loader chỉ resolve, không mở target | không | chỉ static PE evidence (nếu quét file) |
| B05 | benign | một vùng RWX same-process (JIT) | không | tối đa `suspicious`, không alert |
| B06 | benign | `OpenProcess` quyền query yếu | không | relation nhẹ, không alert |
| P01 | PoC | `crt`: `CreateRemoteThread(LoadLibraryW)` | có | access + relation + remote thread + graph |
| P02 | PoC | `nt`: `NtCreateThreadEx` cùng tham số | có | như P01, không phụ thuộc tên API |
| P03 | PoC | `stub`: private RW → RX + thread | có | RW→RX (`rx_anomaly`) + injection behavior |
| P04 | PoC | `apc`: queue trên thread có sẵn | không thấy trong cửa sổ | không có remote thread; vẫn alert nhờ memory/graph/access |
| P05 | PoC | `section`: pagefile section → RX + thread | có | section-backed RX + graph |
| P06 | PoC | `stub` với API label bị xóa | có | alert từ hành vi, không từ chuỗi |
| P07 | PoC | `NtCreateThreadEx` tại code có sẵn trong image | có | remote thread + graph; không cần RWX mới |
| P08 | PoC | Sysmon EID 10/8 + noise benign | có | correlation từ Sysmon |
| X01 | stress | debugger hợp lệ làm cùng chuỗi | không | alert (false positive có chủ đích) |
| X02 | stress | installer query yếu + image load | không | không alert |
| X03 | stress | injector Win32 cổ điển, IAT lộ | không (static) | static chỉ supporting, cần runtime |
| X04 | stress | X03 qua runtime telemetry | có | alert |

B01–B06 và P01–P08 là **core benchmark**. X01–X04 là **stress set** dùng để
phân tích giới hạn, không trộn vào chỉ số chính.

## 2. Biến thể resolver

Năm binary được build từ cùng source:

| Binary | Hàm băm | Seed | Chuỗi API trong binary | Static detector |
|---|---|---|---:|---|
| `footless_loader.exe` | FNV-1a | `0x13579bdf` | có (log/selftest) | hash loop + PEB + IAT gap |
| `footless_loader_seeded.exe` | rotate/xor/add | `0x13579bdf` | có | hash loop + PEB + IAT gap |
| `footless_loader_module_api.exe` | `module:api` rotate/xor/add | `0x13579bdf` | có | hash loop + PEB + IAT gap |
| `footless_loader_quiet.exe` | FNV-1a | `0x13579bdf` | **không** | hash loop + PEB + IAT gap |
| `footless_loader_seed_alt.exe` | FNV-1a | `0xdeadbeef` | có | hash loop + PEB + IAT gap |

Kết quả static (chạy `python main.py <binary>` trong detector):

| Binary | Evidence | Verdict |
|---|---|---|
| baseline | hash_loop, dynamic_resolve, import_anomaly | alert (7) |
| seeded | hash_loop, dynamic_resolve, import_anomaly | alert (7) |
| module-api | hash_loop, dynamic_resolve, import_anomaly | alert (7) |
| quiet | hash_loop, dynamic_resolve, import_anomaly | alert (7) |
| seed-alt | hash_loop, dynamic_resolve, import_anomaly | alert (7) |
| benign_app | none | clean |
| target | none | clean |
| marker.dll | none | clean |

**Kết luận:** đổi thuật toán, thứ tự khóa và seed không làm mất khả năng
phát hiện static. Detector bám vào cấu trúc (loop + PEB + IAT gap), không
bám vào một giá trị hash cụ thể. Việc xóa chuỗi API cũng không đủ để né.

## 3. Biến thể injection và trade-off

| Thay đổi | Khả năng quan sát | Ảnh hưởng detector | Chi phí/ghi chú |
|---|---|---|---|
| `crt` → `nt` | cùng source→target, new thread | không đổi recall; đổi API name/status | cần resolve thêm NtCreateThreadEx |
| `crt/nt` → `stub` | thêm RW→RX transition | thêm `rx_anomaly`, `injection_behavior` | thêm 2 allocation, 1 protect |
| `stub` → `section` | bớt private allocation, thêm section map | `memory_backing=pagefile_section`, vẫn alert | thêm section object, unmap cleanup |
| `crt` → `apc` | không có new thread | bỏ `remote_thread`; vẫn alert nhờ memory+graph+access | cần target alertable |
| API label bị xóa | log mất tên API | runtime vẫn alert; static vẫn alert | giảm khả năng đọc log thủ công |
| timeout ngắn | không thấy marker | alert vẫn xảy ra (attempt) | không được coi timeout là benign |

## 4. Đo trade-off bằng ablation

Detector chạy trên 22 scenario core (14 telemetry + 8 PE):

| Cấu hình | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| full (static + static_pe + runtime + memory + access + graph) | 13 | 0 | 9 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| static-only | 5 | 0 | 9 | 8 | 1.000 | 0.385 | 0.556 | 0.000 |
| runtime-only | 8 | 0 | 9 | 5 | 1.000 | 0.615 | 0.762 | 0.000 |
| no-graph | 13 | 0 | 9 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| no-static-pe | 8 | 0 | 9 | 5 | 1.000 | 0.615 | 0.762 | 0.000 |

Đọc bảng:

- **Static-only** bắt 5/5 PE loader nhưng bỏ toàn bộ telemetry (vì telemetry
  không có file để quét). Đây là lý do phải có runtime layer.
- **Runtime-only** bắt 8/8 telemetry nhưng bỏ toàn bộ PE. Đây là lý do phải
  có static layer.
- **no-static-pe** mất `import_anomaly`; loader chỉ còn 2 evidence trong 1
  area nên dừng ở `suspicious`. Điều này cho thấy yêu cầu "ít nhất 2 layer"
  là có tác dụng chống alert một chiều.
- **no-graph** không giảm recall trên bộ này; graph chủ yếu tăng khả năng
  giải thích và bắt các chuỗi mà từng event rời rạc. Báo cáo ghi rõ đây là
  redundancy, không phải layer bắt buộc.

## 5. Stress set và false positive

| Scenario | Nhãn | Kết quả | Giải thích |
|---|---|---|---|
| X01 debugger hợp lệ | benign | alert (FP) | hành vi giống hệt injection; không có chữ ký/allowlist |
| X02 installer | benign | không alert (TN) | chỉ query yếu + image load same-process |
| X03 injector Win32 cổ điển | malicious | không alert (FN static) | IAT lộ API, không có hash loop/PEB |
| X04 X03 qua runtime | malicious | alert (TP) | chuỗi open→write→RX→thread |

Stress set: P=0.50, R=0.50, F1=0.50, FPR=0.50. Đây là **kết quả có chủ đích**
để cho thấy giới hạn của detector hành vi và nhu cầu allowlist/chữ ký trong
triển khai thật. Không dùng stress set để che core benchmark.

## 6. Cách tái lập

```sh
cd Footless-loader && CC=x86_64-w64-mingw32-gcc ./build.sh
cd ../Footless-detector
python datasets/generate_telemetry.py
python evaluate.py
python tools/ablation.py
python evaluate.py --manifest datasets/stress_manifest.csv \
  --out reports/stress_evaluation.json --markdown reports/stress_evaluation.md
```

Thay `datasets/telemetry/*.jsonl` bằng `loader.jsonl`/`telemetry.jsonl` capture
thật trong VM (cùng schema) để có số đo lab thật; quy trình trong
`docs/RUNBOOK.md`.
