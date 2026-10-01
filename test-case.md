# Test Cases

Mục tiêu của test-case là kiểm tra độc lập hai thành phần:

1. Dynamic API Resolution (API Hashing)
2. Process Injection với NT API

Mỗi thành phần phải được test riêng trước khi tích hợp vào loader.

---

## 10.1. Dynamic API Resolution

### TC-API-01 — Resolve API thành công

**Mục tiêu:**
Kiểm tra loader có thể tìm đúng API thông qua API hash.

**Input:**

```text
Module: ntdll.dll
API: NtOpenProcess
```

**Expected:**

```text
Hash được tính chính xác
        ↓
Export được tìm thấy
        ↓
Function Address != NULL
```

**Expected result:**

```text
[PASS] NtOpenProcess resolved
```

---

### TC-API-02 — Resolve nhiều API

**Mục tiêu:**
Kiểm tra resolver có thể resolve toàn bộ nhóm API cần thiết.

**Input:**

```text
ntdll.dll

- NtOpenProcess
- NtAllocateVirtualMemory
- NtWriteVirtualMemory
```

**Expected:**

```text
NtOpenProcess             != NULL
NtAllocateVirtualMemory   != NULL
NtWriteVirtualMemory      != NULL
```

Nếu một API không resolve được:

```text
[FAIL] API resolution
```

---

### TC-API-03 — API không tồn tại

**Mục tiêu:**
Kiểm tra resolver xử lý đúng trường hợp hash không tồn tại.

**Input:**

```text
Module: ntdll.dll
Hash: hash của một API không tồn tại
```

**Expected:**

```text
ResolveExport() → NULL
```

Loader không được crash.

```text
[PASS] Unknown API handled correctly
```

---

### TC-API-04 — Hash consistency

**Mục tiêu:**
Đảm bảo cùng một API luôn tạo ra cùng một hash.

**Test:**

```text
Hash("NtOpenProcess")
Hash("NtOpenProcess")
```

**Expected:**

```text
Hash1 == Hash2
```

Đồng thời kiểm tra:

```text
Hash("NtOpenProcess")
!=
Hash("NtWriteVirtualMemory")
```

---

## 10.2. Process Injection với NT API

Các test bên dưới chỉ kiểm tra **process/memory operations với dữ liệu vô hại**, không yêu cầu chạy shellcode.

### TC-INJ-01 — Open target process

**Mục tiêu:**
Kiểm tra NT API resolver và quyền truy cập process.

**Flow:**

```text
Target PID
   ↓
NtOpenProcess
   ↓
Process Handle
```

**Expected:**

```text
Status == SUCCESS
Handle != NULL
```

Log:

```text
[PASS] Target process opened
```

Sau test:

```text
Close Handle
```

---

### TC-INJ-02 — Allocate remote memory

**Mục tiêu:**
Kiểm tra khả năng cấp phát memory trong process đích.

**Flow:**

```text
Process Handle
      ↓
NtAllocateVirtualMemory
      ↓
Remote Address
```

**Expected:**

```text
NTSTATUS == SUCCESS
Remote Address != NULL
```

Sau khi test xong phải giải phóng vùng nhớ.

```text
[PASS] Remote memory allocated
```

---

### TC-INJ-03 — Write và verify dữ liệu

**Mục tiêu:**
Kiểm tra dữ liệu được ghi chính xác vào vùng nhớ của process đích.

Sử dụng một buffer vô hại, ví dụ:

```text
TEST_PAYLOAD
```

Flow:

```text
Local Buffer
     ↓
NtWriteVirtualMemory
     ↓
Remote Memory
     ↓
Verify
```

**Expected:**

```text
BytesWritten == PayloadSize
```

và dữ liệu đọc/kiểm tra lại phải giống dữ liệu ban đầu.

```text
[PASS] Remote memory content verified
```

---

### TC-INJ-04 — Cleanup

**Mục tiêu:**
Kiểm tra loader không để lại resource sau khi test.

Kiểm tra:

```text
Process Handle → closed
Remote Memory  → freed
Temporary Buffer → cleared
```

**Expected:**

```text
[PASS] Cleanup completed
```

---

## 10.3. Integration Test

Sau khi tất cả test riêng lẻ PASS, chạy integration test:

```text
Initialize Resolver
        ↓
Resolve NT APIs
        ↓
Open Test Process
        ↓
Allocate Test Memory
        ↓
Write Benign Test Data
        ↓
Verify Data
        ↓
Free Memory
        ↓
Close Process Handle
```

Expected log:

```text
[+] Resolver initialized
[+] NtOpenProcess resolved
[+] NtAllocateVirtualMemory resolved
[+] NtWriteVirtualMemory resolved
[+] Target process opened
[+] Remote memory allocated
[+] Test data written
[+] Test data verified
[+] Remote memory freed
[+] Process handle closed

[PASS] Integration test
```

---

## 10.4. Test Matrix

| ID        | Component   | Test              | Expected                 |
| --------- | ----------- | ----------------- | ------------------------ |
| TC-API-01 | API Hashing | Resolve một API   | Address != NULL          |
| TC-API-02 | API Hashing | Resolve nhiều API | Tất cả thành công        |
| TC-API-03 | API Hashing | API không tồn tại | Trả về NULL, không crash |
| TC-API-04 | API Hashing | Hash consistency  | Hash giống nhau          |
| TC-INJ-01 | NT API      | Open process      | Handle hợp lệ            |
| TC-INJ-02 | NT API      | Allocate memory   | Address hợp lệ           |
| TC-INJ-03 | NT API      | Write + verify    | Dữ liệu chính xác        |
| TC-INJ-04 | NT API      | Cleanup           | Không còn resource       |
| TC-INT-01 | Integration | Chạy toàn bộ flow | Tất cả PASS              |

---

## 10.5. Điều kiện hoàn thành

Phần **Dynamic API Resolution** được xem là hoàn thành khi:

```text
TC-API-01 ✓
TC-API-02 ✓
TC-API-03 ✓
TC-API-04 ✓
```

Phần **Process Injection với NT API** được xem là hoàn thành khi:

```text
TC-INJ-01 ✓
TC-INJ-02 ✓
TC-INJ-03 ✓
TC-INJ-04 ✓
```

Cuối cùng:

```text
TC-INT-01 ✓
```

thì hai module có thể được tích hợp vào loader.
