# Thu bằng chứng và bàn giao detector

## Trước khi chạy

- Chụp tên VM/OS, kiến trúc x64, snapshot và cấu hình lab. Không coi việc đã có VM là đã có snapshot.
- Lưu SHA256, build log, version sensor và cấu hình đang dùng. Runner ghi binary hash và thông tin OS.
- Bật sensor trước target/injector; dùng Run ID mới mỗi ca. Tách thư mục bằng chứng Win7/Win11.
- Quyền injector/target cùng mức. Nếu có lỗi quyền, giữ nguyên log lỗi để phân tích trước khi đổi quyền.

## Sysmon trong Win11

Tài liệu [Sysmon hiện tại](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) liệt kê client Windows 11 trở lên. Không mặc định bản mới chạy trên Win7. Trên Win7 dùng sensor/công cụ tương thích mà nhóm đã kiểm chứng và ghi version; nếu chưa có thì ghi `telemetry unavailable`, không coi là detector không cảnh báo.

`telemetry/sysmon-lab.xml` là cấu hình mẫu thu hẹp theo process của lab; schema cần được kiểm tra với bản sensor trong VM. Việc lọc thu theo tên lab chỉ giảm noise của dataset, không phải rule detector.

Nếu VM đã có Sysmon, lưu cấu hình hiện tại trước khi thay đổi. Với VM dành riêng cho môn học và bản standalone phù hợp, thực hiện bước cài/cấu hình bằng console Administrator **trong guest**:

```powershell
# Xem version/schema của binary đã chuẩn bị từ nguồn Microsoft
.\Sysmon64.exe -s
# Cài lần đầu trên VM chưa có Sysmon:
.\Sysmon64.exe -accepteula -i .\telemetry\sysmon-lab.xml
# Hoặc cập nhật cấu hình của standalone Sysmon đã cài, sau khi lưu cấu hình cũ:
.\Sysmon64.exe -c .\telemetry\sysmon-lab.xml
```

Các lệnh này không được tự chạy bởi runner. Nếu dùng Sysmon tích hợp sẵn hoặc sensor do nhóm quản lý, dùng quy trình cấu hình của sensor đó; không cài chồng hai bản. Thu một ca pilot và kiểm tra Event 1/5/7/8/10 theo mục tiêu trước khi đo cả suite.

Sau mỗi lần chạy:

```powershell
.\scripts\collect-sysmon.ps1 -RunDirectory '.\evidence\<suite>\<run>'
```

Collector xuất EVTX đúng khoảng thời gian, rồi normalize EventData sang `telemetry.jsonl`. Nó không sửa event log nguồn, không đọc marker để sinh quyết định detector. Chạy khi còn quyền đọc channel và log chưa bị rollover. Nếu EVTX đã tồn tại thì giữ nguyên bản gốc và không ghi đè. Giữ cả `telemetry-status.json` khi thu lỗi.

Schema JSONL sensor:

```text
event_id, record_id, utc, provider,
data: các EventData gốc (SourceProcessGuid, TargetProcessGuid,
      SourceProcessId, TargetProcessId, StartAddress, Image, ImageLoaded, ...)
```

Các trường phụ thuộc Event ID và sensor/version; không tự điền trường còn thiếu. Collector giữ mọi event phù hợp trong window; detector chịu trách nhiệm correlation. Một tệp rỗng không xác nhận sensor đã bật đủ các lớp event.

## Ảnh/video tối thiểu cho mỗi phương pháp

1. Target in READY, thấy Run ID/PID/TID; injector chạy ở tiến trình khác.
2. Marker log có cùng Run ID, PID đúng target và TID tương ứng.
3. CRT/NT: `remote_thread` ghi start address/new TID; đối chiếu Event 8 nếu có. Có thể dùng debugger/Process Explorer/Process Monitor trong VM để bổ sung quan sát; ghi đúng tên và version công cụ.
4. DLL: log `dll_module` xác nhận base/path trước marker; ảnh ImageLoad/sensor; marker phase và unload. Vì DLL được unload nhanh, sensor log giữ bằng chứng tốt hơn việc nhìn module list sau khi chạy.
5. APC: quay cả P03 và P04, thấy queue result và marker outcome trong thời hạn. Không lấy ảnh queue success làm ảnh callback executed.
6. Kết thúc: exit code, cleanup hoặc lý do deferred, vị trí thư mục evidence.

Đặt tên `P01-<run>-marker.png`, `P02-<run>-module.png`, `P03-<run>-alertable.mp4`... Không chỉnh PID/TID hoặc nội dung log trong ảnh. Không dùng ảnh từ `verification/` làm bằng chứng injection.

## Hợp đồng với người làm detector

Input detector chỉ là dữ liệu quan sát độc lập. `marker.jsonl`, `injector.jsonl` và counter là dữ liệu đánh giá/debug; không dùng để nhận diện injection. Thông tin target/PID/window được dùng để ghép quyết định theo run sau khi rule chạy, không làm feature thay thế hành vi.

Output theo CSV:

```csv
run_id,detector_result,telemetry_evidence,detector_version
```

Không có hàng ví dụ thành công giả trong template. `detector_result` chỉ nhận `alert`, `no_alert`, `not_evaluated`. Mỗi quyết định đã đánh giá phải có nguồn telemetry và version rule/model. Evaluator chỉ kiểm tra trường provenance đã được điền; người đánh giá vẫn phải xác minh file, coverage và tính độc lập của sensor.

Không dùng `no_alert` khi sensor không cài, thiếu event class, collector bị từ chối quyền hoặc detector chưa chạy. Với APC, nếu sensor chỉ có remote-thread event thì cần ghi coverage thiếu trước khi kết luận.

## Checklist bàn giao

| Sản phẩm | Tình trạng hiện tại |
|---|---|
| Source target, marker DLL, injector và NT comparison | Đã viết, build x64 qua |
| Lý thuyết, 3 sơ đồ, bảng so sánh, kịch bản | Có trong tài liệu |
| Script build/run/collect/evaluate, template CSV | Có; runner/collector mới kiểm tra cú pháp, chưa tích hợp trong VM |
| Binary + SHA256 + build log | Có ở `bin/` |
| Kiểm tra host | Có ở `verification/`, không phải PoC |
| Log thực thi và kết quả VM | Chưa thu |
| Ảnh/video minh chứng | Chưa thu |
| Detector và số đo Precision/Recall/F1/FPR | Chưa triển khai/chưa đánh giá |
| Tương thích runtime Win7/Win11 | Chờ kiểm chứng trên guest thực tế |

Sau khi hoàn tất, chuyển log thô, sensor config và quyết định detector cùng version source/binary. Giữ failure runs; không chỉ chọn các lần thành công.
