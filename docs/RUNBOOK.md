# Runbook — chạy PoC trong VM và tái lập

Tài liệu này phục vụ hạng mục D: cấu hình VM, checklist an toàn, chạy ca,
thu log, xác minh marker và chạy detector. Mọi thao tác thực hiện **trong VM
có snapshot**, không chạy trên máy thật.

## 1. Chuẩn bị VM

- VirtualBox/Hyper-V, Windows 10/11 x64 hoặc Windows 7 x64 (không dùng bản x86).
- Cấp 2 vCPU, 4 GB RAM, 40 GB disk; network host-only hoặc NAT không Internet.
- Tắt shared clipboard/shared folder nếu không cần; không mount ổ host.
- Cài đủ runtime cho `footless_loader.exe` (MinGW static-libgcc, không cần
  Visual C++ redistributable).
- **Tạo snapshot** và ghi tên, ví dụ `Win11-before-Footless`. Snapshot là
  điều kiện bắt buộc; script chỉ xác nhận người chạy đã tạo, không tự kiểm
  tra VirtualBox.

Checklist an toàn:

- [ ] Chỉ chạy trong VM lab, không phải máy thật.
- [ ] Đã có snapshot/rollback và đã thử rollback một lần.
- [ ] Không có C2/Internet; không có dữ liệu thật trong VM.
- [ ] Chỉ dùng target `footless_target.exe` (hoặc `notepad.exe`).
- [ ] Chỉ dùng marker DLL do lab build.
- [ ] Biết cách tắt VM và khôi phục snapshot sau mỗi suite.
- [ ] Không bật shared folder chứa dữ liệu nhạy cảm.

## 2. Build và copy

Trên host (Linux/WSL) hoặc trong VM:

```sh
CC=x86_64-w64-mingw32-gcc ./build.sh
```

Copy `dist/footless_loader*.exe`, `dist/footless_target.exe`,
`dist/footless_marker.dll`, `dist/benign_app.exe` vào một thư mục ngắn trong
VM, ví dụ `C:\Footless\bin`.

Windows build:

```powershell
cd C:\Footless
.\build.ps1
```

## 3. Sysmon (tùy chọn nhưng nên có)

Trong VM, dùng Sysmon standalone từ Microsoft:

```powershell
.\Sysmon64.exe -accepteula -i .\telemetry\sysmon-footless.xml
# hoặc cập nhật cấu hình đã có sau khi lưu bản cũ:
.\Sysmon64.exe -c .\telemetry\sysmon-footless.xml
```

Cấu hình chỉ thu process của lab (EID 1/5/7/8/10) để giảm noise; đây là
**thu hẹp dataset**, không phải rule detector. Kiểm tra channel:

```powershell
Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational
```

Không cài chồng hai bản Sysmon. Ghi lại version và cấu hình đang dùng.

## 4. Chạy một ca

```powershell
$env:FOOTLESS_LAB_CONFIRM = '1'
$env:FOOTLESS_VM_SNAPSHOT = 'Win11-before-Footless'

cd C:\Footless
.\scripts\run_lab.ps1 -SnapshotName $env:FOOTLESS_VM_SNAPSHOT `
    -VmSnapshotConfirmed -Method stub -Scenario P03 -Seconds 20
```

Runner:

1. Tạo `evidence/<suite>/<run>/`.
2. Ghi `environment.json`, SHA256 binary, build log.
3. Chạy target, đợi `READY`.
4. Chạy loader với `--pid`, `--method`, `--run`, `--log loader.jsonl`.
5. Đợi target kết thúc, đọc `marker.jsonl`.
6. Ghi `results.csv` với exit code, marker PID/TID, kết luận.

Các method:

```powershell
-Method crt|nt|stub|apc|section
```

Với `apc`, runner dùng TID đầu tiên của target; target dùng `SleepEx(25, TRUE)`.
Nếu không thấy marker trong cửa sổ, kết quả là `queued_no_marker_in_window`
(chấp nhận cho P04), không phải benign.

## 5. Chạy thủ công để quay video

Mở hai cửa sổ PowerShell tại `C:\Footless\bin`:

```powershell
$env:FOOTLESS_MARKER_LOG='C:\Footless\manual-P03\marker.jsonl'
$env:FOOTLESS_RUN_ID='ManualP03'
.\footless_target.exe ManualP03 30
```

Khi target in `READY`, cửa sổ thứ hai:

```powershell
$env:FOOTLESS_LAB_CONFIRM='1'
$env:FOOTLESS_VM_SNAPSHOT='Win11-before-Footless'
New-Item -ItemType Directory -Force C:\Footless\manual-P03 | Out-Null
.\footless_loader.exe inject --pid <PID> --method stub --run ManualP03 `
    --log C:\Footless\manual-P03\loader.jsonl
```

Quay được: target READY (PID/TID), loader chạy process khác, marker.jsonl
xuất hiện với PID target, và detector alert trên `loader.jsonl`.

## 6. Thu telemetry và xác minh

```powershell
.\scripts\collect_sysmon.ps1 -RunDirectory .\evidence\<suite>\<run>
python3 .\scripts\verify_marker.py --run-dir .\evidence\<suite>\<run>
```

- `collect_sysmon.ps1` xuất EVTX + `telemetry.jsonl` cho đúng cửa sổ thời
  gian; không sửa log nguồn, không cài sensor.
- `verify_marker.py` so khớp marker PID với target PID đã ghi trong
  `run.json`, và với `new_tid` của thread (CRT/NT/section/stub) hoặc TID
  có sẵn (APC).
- Nếu sensor không bật đủ event class, ghi `telemetry_status` là thiếu
  coverage; **không** coi file rỗng là `no_alert`.

## 7. Chạy detector

```powershell
cd C:\Footless\detector
python main.py C:\Footless\evidence\<suite>\<run>\loader.jsonl
python main.py C:\Footless\evidence\<suite>\<run>\telemetry.jsonl
```

Xuất JSON gồm `evidence`, `alert`, `verdict`. Để tính chỉ số trên nhiều run,
tạo manifest CSV (xem `datasets/manifest.csv`) trỏ tới các file thật và:

```sh
python evaluate.py --manifest datasets/my_vm_manifest.csv
```

## 8. Lặp lại và rollback

- Mỗi suite dùng Run ID mới; không tái sử dụng thư mục.
- Sau mỗi suite, rollback snapshot về trạng thái sạch.
- Giữ cả run lỗi; không chỉ chọn run thành công.
- Ghi OS build, Sysmon version/config, quyền chạy, thời gian, hash binary.

## 9. Troubleshooting

| Triệu chứng | Nguyên nhân thường gặp |
|---|---|
| `Refused: set FOOTLESS_LAB_CONFIRM=1` | chưa đặt gate |
| `API table initialization failed` | module/export hash không khớp seed build; rebuild đúng binary |
| `target_path_architecture_or_lifetime_check` | target x86/WOW64, sai path, hoặc đã thoát |
| `create_thread` fail | access denied, target đã thoát, ABI/start address sai |
| APC queue thành công nhưng không marker | thread không alertable hoặc hết thời gian |
| `marker.jsonl` rỗng | DLL không load, DllMain lỗi, hoặc marker path không ghi được |
| Sysmon không có EID 8 | chưa bật đúng config hoặc target image khác filter |
| Detector `alert` trên run benign | xem X01 stress set; kiểm tra allowlist/chữ ký |

## 10. Checklist bằng chứng tối thiểu

- [ ] `build.log` + `sha256.txt` cho từng binary.
- [ ] `environment.json` (OS, snapshot, quyền, sensor).
- [ ] `loader.jsonl` (telemetry) và `marker.jsonl` (ground truth).
- [ ] `results.csv` cho suite.
- [ ] EVTX/`telemetry.jsonl` (nếu có Sysmon).
- [ ] Ảnh/video: READY, loader ở process khác, marker PID/TID, detector alert.
- [ ] `reports/evaluation.json` + `evaluation.md` từ detector.
- [ ] Ghi rõ run lỗi và lý do; không xóa.
