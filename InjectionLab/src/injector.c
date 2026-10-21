#include "lab.h"
#include <tlhelp32.h>

/* User-mode Native API declaration; no syscall numbers or bypass flags. See docs/report.md. */
typedef LONG (NTAPI *NtCreateThreadExFn)(PHANDLE, ACCESS_MASK, PVOID, HANDLE,
    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
static LabShared lab;
static HANDLE process;
static BOOL log_ok=TRUE;
static BOOL release_remote(LPVOID memory);

static void trace(const char *event, const char *fmt, ...) {
    char detail[12000];va_list args;
    va_start(args,fmt);vsnprintf(detail,sizeof(detail),fmt,args);va_end(args);
    if(!lab_log(lab.output,L"injector.jsonl",lab.run,lab.scenario,event,"%s",detail)) log_ok=FALSE;
}
static void failure(const char *stage, DWORD code) {
    trace("error",",\"stage\":\"%s\",\"win32_error\":%lu",stage,code);
    fprintf(stderr,"%s failed: Win32 %lu\n",stage,code);
}
static HANDLE remote_thread(ULONGLONG start, LPVOID param, BOOL use_nt, const char *phase) {
    HANDLE thread=NULL;DWORD tid=0;
    ULONGLONG begin=GetTickCount64();
    if(use_nt) {
        NtCreateThreadExFn nt=(NtCreateThreadExFn)(uintptr_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtCreateThreadEx");
        if(!nt) {failure("resolve_NtCreateThreadEx",GetLastError());return NULL;}
        LONG status=nt(&thread,THREAD_QUERY_INFORMATION|SYNCHRONIZE,NULL,process,
                       (PVOID)(uintptr_t)start,param,0,0,0,0,NULL);
        trace("nt_status",",\"ntstatus\":\"0x%08lx\",\"flags\":0",(unsigned long)status);
        if(status<0 || !thread) return NULL;
        tid=GetThreadId(thread);
    } else {
        thread=CreateRemoteThread(process,NULL,0,(LPTHREAD_START_ROUTINE)(uintptr_t)start,param,0,&tid);
        if(!thread) {failure("CreateRemoteThread",GetLastError());return NULL;}
    }
    trace("remote_thread",",\"api\":\"%s\",\"phase\":\"%s\",\"target_pid\":%lu,\"new_tid\":%lu,"
        "\"start_address\":\"0x%llx\",\"argument\":\"0x%llx\",\"call_duration_ms\":%llu",
        use_nt?"NtCreateThreadEx":"CreateRemoteThread",phase,lab.pid,tid,start,
        (ULONGLONG)(uintptr_t)param,GetTickCount64()-begin);
    return thread;
}
/* Returns only after confirmed thread termination. A timeout retains remote buffers. */
static BOOL finish_thread(HANDLE thread, DWORD timeout, DWORD *exit_code) {
    DWORD wait=WaitForSingleObject(thread,timeout);
    DWORD wait_error=wait==WAIT_FAILED?GetLastError():0;
    trace("thread_wait",",\"wait_result\":%lu,\"timeout_ms\":%lu",wait,timeout);
    if(wait!=WAIT_OBJECT_0) {
        if(wait==WAIT_FAILED) failure("WaitForSingleObject",wait_error);
        CloseHandle(thread);return FALSE;
    }
    BOOL ok=GetExitCodeThread(thread,exit_code);
    if(!ok) failure("GetExitCodeThread",GetLastError());
    else trace("thread_exit",",\"exit_code\":%lu",*exit_code);
    CloseHandle(thread);
    return ok;
}
static LPVOID remote_bytes(const void *bytes, SIZE_T size, BOOL executable) {
    LPVOID memory=VirtualAllocEx(process,NULL,size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!memory) {failure("VirtualAllocEx",GetLastError());return NULL;}
    trace("allocation",",\"target_pid\":%lu,\"address\":\"0x%llx\",\"bytes\":%llu,\"protection\":\"RW\"",
          lab.pid,(ULONGLONG)(uintptr_t)memory,(ULONGLONG)size);
    SIZE_T written=0;
    if(!WriteProcessMemory(process,memory,bytes,size,&written) || written!=size) {
        failure("WriteProcessMemory",GetLastError());release_remote(memory);return NULL;
    }
    trace("write",",\"bytes_written\":%llu",(ULONGLONG)written);
    if(executable) {
        DWORD old=0;
        if(!VirtualProtectEx(process,memory,size,PAGE_EXECUTE_READ,&old) ||
           !FlushInstructionCache(process,memory,size)) {
            failure("protect_or_flush",GetLastError());release_remote(memory);return NULL;
        }
        trace("protection",",\"address\":\"0x%llx\",\"old\":%lu,\"new\":\"RX\"",(ULONGLONG)(uintptr_t)memory,old);
    }
    return memory;
}
static BOOL release_remote(LPVOID memory) {
    BOOL ok=VirtualFreeEx(process,memory,0,MEM_RELEASE);DWORD err=ok?0:GetLastError();
    trace("free",",\"address\":\"0x%llx\",\"ok\":%s,\"win32_error\":%lu",(ULONGLONG)(uintptr_t)memory,ok?"true":"false",err);
    return ok;
}
static ULONGLONG find_dll(BOOL *scan_ok) {
    *scan_ok=FALSE;
    HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,lab.pid);
    if(snapshot==INVALID_HANDLE_VALUE) {failure("module_snapshot",GetLastError());return 0;}
    MODULEENTRY32W entry;ZeroMemory(&entry,sizeof(entry));entry.dwSize=sizeof(entry);
    ULONGLONG base=0;
    if(!Module32FirstW(snapshot,&entry)) {
        failure("module_first",GetLastError());CloseHandle(snapshot);return 0;
    }
    for(;;) {
        if(!_wcsicmp(entry.szExePath,lab.dll)) {base=(ULONGLONG)(uintptr_t)entry.modBaseAddr;*scan_ok=TRUE;break;}
        if(!Module32NextW(snapshot,&entry)) {
            DWORD error=GetLastError();
            if(error==ERROR_NO_MORE_FILES) *scan_ok=TRUE;
            else failure("module_next",error);
            break;
        }
    }
    CloseHandle(snapshot);return base;
}
static int demo_stub(BOOL apc, BOOL use_nt, DWORD timeout, const LabShared *view) {
    /* Fixed benign x64 stub: mov rax, target-owned marker; jmp rax.
       Tail jump preserves the caller's ABI stack and the marker returns to Windows.
       No externally supplied shellcode or arbitrary entry point is accepted. */
    unsigned char stub[12]={0x48,0xb8,0,0,0,0,0,0,0,0,0xff,0xe0};
    ULONGLONG callback=apc?lab.apc_fn:lab.marker_fn;
    memcpy(stub+2,&callback,8);
    LPVOID remote=remote_bytes(stub,sizeof(stub),TRUE);
    if(!remote) return 10;
    LONG before=view->markers;
    trace("stub",",\"length\":12,\"target_callback\":\"0x%llx\",\"callback_type\":\"%s\"",callback,apc?"APC":"ThreadProc");
    if(apc) {
        HANDLE thread=OpenThread(THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,lab.tid);
        if(!thread) {failure("OpenThread",GetLastError());release_remote(remote);return 10;}
        if(GetProcessIdOfThread(thread)!=lab.pid) {
            failure("thread_owner_check",ERROR_INVALID_PARAMETER);CloseHandle(thread);release_remote(remote);return 10;
        }
        DWORD queued=QueueUserAPC((PAPCFUNC)(uintptr_t)remote,thread,0);
        DWORD err=queued?0:GetLastError();CloseHandle(thread);
        trace("apc_queue",",\"queued\":%s,\"target_pid\":%lu,\"existing_tid\":%lu,\"callback_address\":\"0x%llx\",\"win32_error\":%lu",
              queued?"true":"false",lab.pid,lab.tid,(ULONGLONG)(uintptr_t)remote,err);
        if(!queued) {release_remote(remote);return 10;}
        ULONGLONG end=GetTickCount64()+timeout;
        while(GetTickCount64()<end && view->markers==before && WaitForSingleObject(process,0)==WAIT_TIMEOUT) Sleep(10);
        BOOL observed=view->markers>before;
        trace("apc_observation",",\"marker_counter_changed\":%s,\"observation_limit_ms\":%lu",observed?"true":"false",timeout);
        /* Even a completed marker log is not proof of callback return. Keep allocation
           for process lifetime, including a nonalertable thread's pending APC. */
        trace("cleanup_deferred",",\"reason\":\"APC lifetime; OS reclaims allocation on target exit\",\"address\":\"0x%llx\"",(ULONGLONG)(uintptr_t)remote);
        return observed?0:20;
    }
    HANDLE thread=remote_thread((ULONGLONG)(uintptr_t)remote,NULL,use_nt,"stub_marker");
    if(!thread) {release_remote(remote);return 10;}
    DWORD code=0;
    if(!finish_thread(thread,timeout,&code)) {
        trace("cleanup_deferred",",\"reason\":\"thread termination unconfirmed; retained until target exit\"");return 21;
    }
    BOOL freed=release_remote(remote);
    return code==0 && freed && view->markers>before?0:11;
}
static int demo_dll(DWORD timeout) {
    BOOL scan_ok=FALSE;
    ULONGLONG previous=find_dll(&scan_ok);
    if(!scan_ok) return 10;
    if(previous) {failure("DLL_must_not_be_preloaded",ERROR_ALREADY_EXISTS);return 10;}
    HMODULE local=LoadLibraryW(lab.dll);
    if(!local) {failure("local_marker_DLL_load",GetLastError());return 10;}
    FARPROC symbol=GetProcAddress(local,"Nt230DllMarker");
    if(!symbol) {failure("marker_export",GetLastError());FreeLibrary(local);return 10;}
    ULONGLONG rva=(ULONGLONG)((uintptr_t)symbol-(uintptr_t)local);
    FreeLibrary(local);
    LPVOID path=remote_bytes(lab.dll,(wcslen(lab.dll)+1)*sizeof(WCHAR),FALSE);
    if(!path) return 10;
    char dllpath[LAB_PATH*8];lab_json_wide(lab.dll,dllpath,sizeof(dllpath));
    trace("dll_request",",\"dll_path\":\"%s\",\"marker_export_rva\":\"0x%llx\"",dllpath,rva);
    HANDLE thread=remote_thread(lab.load_fn,path,FALSE,"LoadLibraryW");
    if(!thread) {release_remote(path);return 10;}
    DWORD code=0;
    if(!finish_thread(thread,timeout,&code)) {
        trace("cleanup_deferred",",\"reason\":\"loader still potentially using DLL path\"");return 21;
    }
    BOOL freed=release_remote(path);
    /* Thread exit code is only DWORD: never treat it as a 64-bit HMODULE. */
    ULONGLONG base=find_dll(&scan_ok);
    if(!scan_ok) return 12;
    trace("dll_module",",\"loaded\":%s,\"base\":\"0x%llx\",\"dll_path\":\"%s\"",base?"true":"false",base,dllpath);
    if(!base) return 12;
    thread=remote_thread(base+rva,NULL,FALSE,"Nt230DllMarker");
    if(!thread) {
        trace("cleanup_deferred",",\"reason\":\"marker thread creation failed; DLL retained until target exit\"");return 10;
    }
    if(!finish_thread(thread,timeout,&code)) {
        trace("cleanup_deferred",",\"reason\":\"marker may still execute; DLL retained\"");return 21;
    }
    BOOL marker_ok=(code==0);
    thread=remote_thread(lab.free_fn,(LPVOID)(uintptr_t)base,FALSE,"FreeLibrary");
    if(!thread) {
        trace("cleanup_deferred",",\"reason\":\"unload thread creation failed; DLL retained until target exit\"");return 10;
    }
    if(!finish_thread(thread,timeout,&code)) {
        trace("cleanup_deferred",",\"reason\":\"unload thread completion unconfirmed\"");return 21;
    }
    ULONGLONG remaining=find_dll(&scan_ok);
    BOOL unloaded=scan_ok && !remaining;
    trace("dll_unload",",\"unloaded\":%s,\"FreeLibrary_return\":%lu",unloaded?"true":"false",code);
    return marker_ok && unloaded && freed && code?0:13;
}

int wmain(int argc, WCHAR **argv) {
    if(argc!=4) {
        fwprintf(stderr,L"Usage: NT230_injector.exe crt|dll|apc|nt|nt-image RUN OBSERVE_MS\n");return 2;
    }
    if(!lab_token(argv[2]) || !lab_gate()) return 2;
    BOOL image=!wcscmp(argv[1],L"nt-image");
    BOOL apc=!wcscmp(argv[1],L"apc"),nt=!wcscmp(argv[1],L"nt") || image,dll=!wcscmp(argv[1],L"dll");
    if(!apc && !nt && !dll && wcscmp(argv[1],L"crt")) return 2;
    WCHAR *end=NULL;unsigned long timeout=wcstoul(argv[3],&end,10);
    if(!end || *end || timeout<100 || timeout>60000) return 2;
    WCHAR name[128];lab_map_name(name,argv[2]);
    HANDLE mapping=OpenFileMappingW(FILE_MAP_READ|FILE_MAP_WRITE,FALSE,name);
    if(!mapping) {fwprintf(stderr,L"No opted-in lab target for RUN %ls; error %lu\n",argv[2],GetLastError());return 3;}
    LabShared *view=(LabShared*)MapViewOfFile(mapping,FILE_MAP_READ|FILE_MAP_WRITE,0,0,sizeof(LabShared));
    if(!view) {CloseHandle(mapping);return 3;}
    memcpy(&lab,view,sizeof(lab));
    int result=3;
    if(lab.version!=LAB_VERSION || !lab.ready || lab.pid==GetCurrentProcessId() ||
       lab.run[79] || lab.scenario[79] || lab.image[LAB_PATH-1] || lab.output[LAB_PATH-1] || lab.dll[LAB_PATH-1] ||
       wcscmp(lab.run,argv[2]) || !lab_token(lab.scenario)) goto done;
    DWORD rights=PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ|SYNCHRONIZE;
    process=OpenProcess(rights,FALSE,lab.pid);
    if(!process) {failure("OpenProcess",GetLastError());goto done;}
    WCHAR expected[LAB_PATH],actual[LAB_PATH];DWORD len=LAB_PATH;BOOL wow64=TRUE;
    if(!lab_sibling(L"NT230_target.exe",expected) ||
       !QueryFullProcessImageNameW(process,0,actual,&len) || _wcsicmp(expected,actual) || _wcsicmp(lab.image,actual) ||
       !IsWow64Process(process,&wow64) || wow64 || WaitForSingleObject(process,0)!=WAIT_TIMEOUT) {
        failure("target_path_architecture_or_lifetime_check",ERROR_INVALID_PARAMETER);goto close_process;
    }
    if(!lab_sibling(L"NT230_marker.dll",expected) || _wcsicmp(expected,lab.dll)) {
        failure("fixed_DLL_path_check",ERROR_INVALID_PARAMETER);goto close_process;
    }
    if(InterlockedCompareExchange(&view->attempted,1,0)!=0) {
        failure("one_injection_per_target_run",ERROR_ALREADY_EXISTS);goto close_process;
    }
    char image_path[LAB_PATH*8];lab_json_wide(actual,image_path,sizeof(image_path));
    trace("source_target",",\"method\":\"%ls\",\"target_pid\":%lu,\"target_tid\":%lu,\"target_image\":\"%s\",\"process_access_mask\":\"0x%lx\"",
          argv[1],lab.pid,lab.tid,image_path,rights);
    if(image) {
        trace("image_start",",\"memory_backing\":\"target image\",\"new_remote_allocation\":false");
        HANDLE thread=remote_thread(lab.marker_fn,NULL,TRUE,"image_marker");
        DWORD code=0;
        result=thread && finish_thread(thread,timeout,&code) && code==0 && view->markers>0?0:11;
    } else result=dll?demo_dll(timeout):demo_stub(apc,nt,timeout,view);
    trace("result",",\"exit_code\":%d,\"thread_apc_marker_counter\":%ld,\"note\":\"ground truth must be verified from target marker log\"",result,view->markers);
close_process:
    CloseHandle(process);
done:
    UnmapViewOfFile(view);CloseHandle(mapping);
    if(!log_ok && result==0) result=30;
    return result;
}
