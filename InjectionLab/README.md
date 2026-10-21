# NT230 — Bộ lab Process Injection

Bộ mã cho phần injection của nhóm D08+D09: target tự viết, marker vô hại, CreateRemoteThread, DLL Injection, APC và phép so sánh NtCreateThreadEx. Không có detector trong bộ mã này. Detector của nhóm cần xử lý telemetry độc lập.

**Trạng thái bàn giao:** build x64 đã thành công; kiểm tra host đã qua. Chưa chạy các ca injection trong VM; chưa có log thực thi VM, ảnh/video hay kết quả detector. `verification/` chỉ chứa kiểm tra kỹ thuật trên host, không phải bằng chứng PoC.

## Đọc đúng đề tài

File đề, sheet `DEV Track`:

- **D08, A12:K12:** API hashing. Cần 3 resolver, phân tích Ghidra, detector static + dynamic/memory. Phần này vẫn cần người triển khai riêng.
- **D09, A13:K13:** Process Injection với NT API. Chọn **NtCreateThreadEx hoặc section mapping**, tạo injector/target tự viết, thu ETW/Sysmon, detector correlation và so sánh CreateRemoteThread.
- Mỗi đề có yêu cầu ≥3 benign + ≥3 PoC/biến thể, Precision/Recall/F1/FPR và khả năng tái lập. Không mặc định bộ dữ liệu injection đáp ứng luôn API hashing của D08.
- Rubric: cơ chế/PoC 3 điểm, biến thể 2 điểm, detector **4 điểm**, đánh giá/tái lập/an toàn 1 điểm. Các quy định an toàn và VM nằm tại `I12:I13` và `DEV Track - Rubric!A10`.

`assignment-extract.json` giữ nguyên nội dung các ô liên quan cùng SHA256 của file đề. File `.xlsm` chỉ được đọc XML, không chạy macro hoặc sửa file.

## Phạm vi mã

| Thành phần | Chức năng |
|---|---|
| `src/target.c` | Target độc lập, xuất phiên lab qua named mapping, kiểm soát alertable wait, tự ghi marker |
| `src/injector.c` | `crt`, `dll`, `apc`, `nt`, `nt-image`; ghi các bước, lỗi và cleanup |
| `src/marker.c` | DLL có DllMain tối giản; export riêng `Nt230DllMarker` ghi marker |
| `scripts/run-lab.ps1` | Chạy từng ca hoặc 9 ca, xác minh PID/TID, lưu bảng kết quả |
| `scripts/collect-sysmon.ps1` | Xuất EVTX gốc và JSONL từ Sysmon đang có |
| `scripts/evaluate.py` | Ghép quyết định detector với ground truth và tính chỉ số |
| `docs/REPORT.md` | Lý thuyết, 3 sơ đồ, bảng so sánh, phân tích NT API và giới hạn |
| `docs/EVIDENCE.md` | Cách thu bằng chứng và hợp đồng dữ liệu cho detector |

Payload của `crt`, `nt`, `apc` là stub x64 cố định **12 byte**, chỉ chuyển điều khiển tới hàm marker có sẵn trong target. Đây là mã máy thực thi trong target; phần ghi file nằm trong hàm marker của target để dễ kiểm chứng. Chương trình không nhận shellcode hoặc DLL tùy ý, không hỗ trợ target bên ngoài bộ lab.

Injector kiểm tra target đúng đường dẫn `bin/NT230_target.exe`, kiến trúc x64 và mapping của Run ID; mỗi target chỉ nhận một lần thử. Mapping là giao thức hợp tác của lab, không phải ranh giới bảo mật trước phần mềm độc hại có cùng quyền người dùng.

## Chuẩn bị VirtualBox

1. Ưu tiên **Win11 x64** cho lần thử đầu. Win7 cũng phải là **x64**; bản x86 không dùng được với stub này.
2. Tạo snapshot, ghi tên và thời điểm. Sao chép toàn bộ `InjectionLab` vào một đường dẫn ngắn trong guest, ví dụ `C:\NT230\InjectionLab`.
3. Dùng PowerShell **5.1 x64**. Win7 mặc định có thể chưa có 5.1: kiểm tra `$PSVersionTable.PSVersion`; chuẩn bị Windows Management Framework phù hợp nếu cần. Các binary native không phụ thuộc Python/PowerShell để hoạt động, nhưng runner cần 5.1.
4. Injector và target chạy cùng user, cùng mức quyền; thông thường không cần Administrator. Việc cài/cấu hình sensor là thao tác riêng trong VM.
5. Ghi Windows edition/build, snapshot, quyền chạy, phiên bản công cụ build và sensor. Runner lưu tự động phần lớn thông tin này trong `environment.json`.

`-VmSnapshotConfirmed` và biến môi trường `NT230_VM_SNAPSHOT` là xác nhận của người chạy, **không tự kiểm tra được snapshot của VirtualBox**. Không đặt chúng trên host để bỏ qua yêu cầu của đề.

## Build

Đã build bằng MinGW-w64 GCC 8.1.0, target `x86_64-w64-mingw32`, với `-Wall -Wextra -Werror`, `_WIN32_WINNT=0x0601` và static libgcc. Công cụ build có thể chạy trên host rồi chuyển cả `bin/` vào VM.

```powershell
cd C:\NT230\InjectionLab
.\build.ps1
# Nếu GCC không có trong PATH:
.\build.ps1 -Compiler 'C:\Program Files\CodeBlocks\MinGW\bin\gcc.exe'
```

Kết quả: `bin/NT230_target.exe`, `bin/NT230_injector.exe`, `bin/NT230_marker.dll`, build log và SHA256. Các thành phần phải nằm cùng thư mục và được build từ cùng phiên bản source.

```powershell
# Kiểm tra không chạy injection: cú pháp script, serialization, gate, evaluator.
.\scripts\verify-local.ps1
```

Kiểm tra này cần Python 3 trên máy thực hiện. Không cần cài Python trong Win7 chỉ để chạy demo; có thể chép CSV sang máy phân tích sau.

## Chạy ca đầu tiên trong VM

Sau khi tạo snapshot thật trong VirtualBox:

```powershell
.\scripts\run-lab.ps1 -SnapshotName 'Win11-before-NT230' -VmSnapshotConfirmed -Scenario P01
```

Runner tự khởi động target thành tiến trình riêng, đợi target ready, chạy injector rồi đối chiếu marker. Đây là một tiến trình độc lập, có PID và vòng đời riêng. Sau khi chạy, đọc `evidence/<suite>/results.csv` và thư mục Run ID:

- `marker.jsonl`: mã lần chạy, scenario, **PID/TID đang thực thi**, UTC và loại marker.
- `target.jsonl`: trạng thái target, TID ban đầu và lúc thoát.
- `injector.jsonl`: PID nguồn, PID đích, remote thread TID/start address, vùng nhớ, lỗi, cleanup.
- `*.stdout.txt`, `*.stderr.txt`: đầu ra thô của từng chương trình.
- `run.json`: kết luận kiểm chứng và khoảng thời gian cho telemetry.

P01 chỉ đạt khi marker PID bằng PID target, marker TID bằng TID remote thread mới, injector trả 0, target trả 0 và cleanup được ghi nhận. Chỉ thấy `WriteProcessMemory` thành công thì chưa đạt.

## Chạy đầy đủ, lặp lại trên từng OS

```powershell
.\scripts\run-lab.ps1 -SnapshotName 'Win11-before-NT230' -VmSnapshotConfirmed -Scenario All -Repeat 3
```

Thực hiện tương tự ở Win7 x64 với snapshot riêng. Không gộp các OS vào một kết quả mà thiếu trường OS/sensor. Chín ca chạy khoảng vài phút tùy cấu hình; mỗi ca dùng target và Run ID mới.

| Ca | Mục đích | Kết quả mong đợi, chưa phải kết quả đo |
|---|---|---|
| B01 | Target chạy bình thường | Không có marker |
| B02 | Target tự nạp DLL và gọi export | Marker DLL trên thread của target |
| B03 | Target tự queue APC hợp lệ | Marker trên thread có sẵn |
| P01 | CreateRemoteThread + stub private RX | Marker trên thread mới |
| P02 | Remote DLL load + gọi marker export | Module đã nạp, marker chạy, DLL được unload |
| P03 | APC + thread alertable | Queue thành công, marker chạy trên TID có sẵn |
| P04 | APC + thread không alertable | Queue thành công, chưa thấy marker trong thời hạn |
| P05 | NtCreateThreadEx + cùng stub P01 | Marker trên thread mới; so sánh trực tiếp P01 |
| P06 | NtCreateThreadEx + hàm marker trong image | Marker chạy, không có cấp phát/ghi remote code mới |

P04 trả **20** theo thiết kế: đã queue nhưng chưa thấy callback trong cửa sổ quan sát. Runner coi đúng kết quả này là `pass`; nó không phải bằng chứng callback sẽ không bao giờ chạy. `marker_executed=no_observed` luôn gắn với thời hạn.

## Chạy thủ công để quay video

Trong guest, mở hai PowerShell tại thư mục `bin`. Tạo sẵn thư mục đầu ra; dùng Run ID mới cho mỗi lần.

```powershell
# Cửa sổ target
$env:NT230_VM_SNAPSHOT='Win11-before-NT230'
New-Item -ItemType Directory -Force C:\NT230\manual-P01 | Out-Null
.\NT230_target.exe ManualP01 P01 idle C:\NT230\manual-P01 30
```

```powershell
# Cửa sổ injector, sau khi target in READY
$env:NT230_VM_SNAPSHOT='Win11-before-NT230'
.\NT230_injector.exe crt ManualP01 2500
```

Thay `crt` bằng `dll`, `nt`, `nt-image`. Với `apc`, đặt mode target là `alertable` hoặc `nonalertable`. Target không nhận lệnh thực thi qua IPC; mapping chỉ cung cấp địa chỉ các hàm marker và thông tin phiên lab.

## Thu telemetry và tính chỉ số

Đọc [hướng dẫn bằng chứng](docs/EVIDENCE.md). Sau mỗi ca, khi sensor đã bật từ trước:

```powershell
.\scripts\collect-sysmon.ps1 -RunDirectory '.\evidence\<suite>\<run>'
```

Script không cài hoặc đổi cấu hình sensor, không chạy detector. Không coi file telemetry rỗng hay thiếu sự kiện là `no_alert` trước khi xác minh coverage. `telemetry-status.json` là trạng thái thu; cột `telemetry_status` ban đầu trong CSV vẫn là `not_collected` cho đến khi nhóm cập nhật/ghép bản thu.

Nhóm detector xuất CSV theo `templates/detector-predictions.csv` với `alert`, `no_alert` hoặc `not_evaluated`, kèm bằng chứng telemetry và phiên bản detector.

```powershell
python .\scripts\evaluate.py .\evidence\<suite>\results.csv .\predictions.csv --output .\metrics.json
```

Evaluator đo **phát hiện injection attempt**, không đo marker đã chạy. Vì vậy P04 vẫn là positive attempt. Các ca lỗi hoặc chưa đánh giá bị loại khỏi mẫu số và được liệt kê; không biến chúng thành true negative. Mẫu số bằng 0 được ghi `null`.

## Phần việc còn lại của nhóm

- Chạy và xác nhận các binary trên Win11/Win7 thật trong VM; tương thích Win7 mới được xét ở mức API/build, chưa kiểm chứng runtime.
- Lưu ảnh/video, EVTX/ETW và cấu hình sensor thực tế; hoàn thiện bảng kết quả và phân tích ca thất bại.
- Triển khai detector D09 độc lập, rồi tính chỉ số từ quyết định thực tế.
- Chỉ định người nhận D08: 3 API resolver, phân tích Ghidra và detector tương ứng. Việc `GetProcAddress` để gọi NtCreateThreadEx trong lab này không phải 3 resolver API hashing.

Không cần làm section mapping để đáp ứng lựa chọn NT API của D09 nếu đã hoàn thiện và chứng minh NtCreateThreadEx. Có thể dùng section mapping làm hướng mở rộng sau.
