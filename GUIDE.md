# Guide

## 1. Mục tiêu

Xây dựng một loader Windows tối giản sử dụng:

* Dynamic API Resolution - API Hashing
* NT API
* Process Injection trong môi trường lab

Không sử dụng:

* DLL sideloading
* Module Stomping
* DLL Hollowing
* Process Hollowing
* AMSI/ETW bypass
* Anti-analysis / Anti-emulation
* Stack spoofing
* C2 staging
* Polymorphic mutation

---

## 2. Kiến trúc

Luồng xử lý chính:

```text
Loader
  │
  ├── 1. Tìm module cần thiết
  │
  ├── 2. Resolve API bằng hash
  │
  ├── 3. Chuẩn bị payload cho lab
  │
  ├── 4. Mở process đích
  │
  ├── 5. Cấp phát memory trong process
  │
  ├── 6. Ghi payload vào memory
  │
  └── 7. Khởi chạy payload
```

Ý tưởng quan trọng:

```text
Không lưu trực tiếp tên API
        ↓
Hash tên API
        ↓
Duyệt export table
        ↓
Tính hash từng export
        ↓
Hash trùng → lấy địa chỉ API
```

---

# 3. Dynamic API Resolution

## 3.1. Hash API

Thay vì:

```c
GetProcAddress(hModule, "NtOpenProcess");
```

loader lưu hash:

```text
HASH("NtOpenProcess")
HASH("NtAllocateVirtualMemory")
HASH("NtWriteVirtualMemory")
...
```

Khi chạy:

```text
Module Base
     ↓
PE Export Table
     ↓
Export Name
     ↓
Hash(Name)
     ↓
Compare với target hash
     ↓
Function Address
```

---

## 3.2. Resolve module

Loader cần tìm base address của module cần thiết.

Có thể sử dụng PEB để tìm các module đã được process load.

Ví dụ kiến trúc:

```text
PEB
 ↓
PEB_LDR_DATA
 ↓
InMemoryOrderModuleList
 ↓
Module
 ↓
BaseDllName
 ↓
Module Base Address
```

Các module cần thiết cho lab có thể giới hạn ở:

```text
ntdll.dll
kernel32.dll
```

---

# 4. Resolve NT API

Sau khi lấy được `ntdll.dll`:

```text
ntdll.dll
   ↓
Export Directory
   ↓
NtOpenProcess
NtAllocateVirtualMemory
NtWriteVirtualMemory
...
```

Mỗi tên API được hash và so sánh với hash đã định nghĩa.

Ví dụ conceptual:

```c
#define HASH_NtOpenProcess       ...
#define HASH_NtAllocateMemory    ...
#define HASH_NtWriteMemory       ...
```

Sau khi resolve:

```text
NtOpenProcess
      ↓
function pointer

NtAllocateVirtualMemory
      ↓
function pointer

NtWriteVirtualMemory
      ↓
function pointer
```

Loader sau đó chỉ sử dụng các function pointer này.

---

# 5. Process Injection

Trong môi trường lab, quy trình injection có thể mô hình hóa thành:

```text
Process A
   │
   │ NtOpenProcess
   ▼
Process B
   │
   │ NtAllocateVirtualMemory
   ▼
Remote Memory
   │
   │ NtWriteVirtualMemory
   ▼
Payload
   │
   │ execution primitive
   ▼
Remote Process
```

Các bước logic:

### Step 1 — Open process

Lấy handle tới process đích bằng NT API.

```text
PID
 ↓
NtOpenProcess
 ↓
Process Handle
```

### Step 2 — Allocate memory

Cấp phát vùng nhớ trong process đích.

```text
Process Handle
      ↓
NtAllocateVirtualMemory
      ↓
Remote Address
```

### Step 3 — Write payload

Ghi dữ liệu lab vào vùng nhớ vừa cấp phát.

```text
Local Payload
      ↓
NtWriteVirtualMemory
      ↓
Remote Memory
```

### Step 4 — Execute

Sử dụng execution primitive phù hợp với lab để chạy code trong process đích.

Trong tài liệu học tập, nên tách phần này thành một module riêng:

```text
Execution
├── memory preparation
└── execution mechanism
```

---

# 6. Project Structure

Giữ project đơn giản:

```text
Loader/
│
├── main.c
├── hash.c
├── hash.h
├── resolver.c
├── resolver.h
├── ntapi.c
├── ntapi.h
├── payload.h
└── README.md
```

### `hash.c`

Chứa:

```text
HashString()
```

Nhiệm vụ:

```text
API name → hash
```

---

### `resolver.c`

Chứa:

```text
FindModule()
ResolveExport()
ResolveApi()
```

Nhiệm vụ:

```text
PEB
 ↓
Module
 ↓
Export Table
 ↓
API Hash
 ↓
Function Address
```

---

### `ntapi.c`

Chứa các wrapper/function pointer cho NT API cần thiết.

Ví dụ conceptual:

```text
NtOpenProcess
NtAllocateVirtualMemory
NtWriteVirtualMemory
```

---

### `main.c`

Chỉ giữ flow chính:

```text
Initialize Resolver
        ↓
Resolve NT APIs
        ↓
Prepare Lab Payload
        ↓
Open Target Process
        ↓
Allocate Remote Memory
        ↓
Write Payload
        ↓
Execute
        ↓
Cleanup
```

---

# 7. Build Flow

Build tối giản:

```text
hash.c
   ↓
resolver.c
   ↓
ntapi.c
   ↓
main.c
   ↓
MSVC
   ↓
loader.exe
```

Không cần:

```text
Encrypt.py
Mutate.py
SideloadGen.py
AsmStub.asm
Payload.h generation
```

nếu mục tiêu chỉ là học Dynamic API Resolution + NT API.

---

# 8. Debug

Nên bắt đầu với:

```text
DEBUG = ON
```

và log:

```text
[+] Resolver initialized
[+] ntdll.dll found
[+] NtOpenProcess resolved
[+] NtAllocateVirtualMemory resolved
[+] NtWriteVirtualMemory resolved
[+] Target process opened
[+] Remote memory allocated
[+] Payload written
```

Sau khi toàn bộ flow hoạt động ổn định mới loại bỏ debug logging.

---

# 9. Tổng kết

Loader tối giản chỉ cần:

```text
                 ┌──────────────┐
                 │     PEB      │
                 └──────┬───────┘
                        │
                        ▼
                Find ntdll.dll
                        │
                        ▼
                Export Table
                        │
                        ▼
                  API Hashing
                        │
                        ▼
              Dynamic API Resolution
                        │
                        ▼
                  NT API calls
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
    Open Process   Allocate Memory   Write Memory
          │             │             │
          └─────────────┼─────────────┘
                        ▼
                  Lab Execution
```

Đây là phiên bản tối giản của kiến trúc trong repository: thay vì pipeline lớn gồm nhiều lớp staging/evasion/placement, chỉ giữ lại **resolver → NT API → remote-memory operation → execution**.
