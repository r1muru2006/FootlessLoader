#include "lab.h"

static LabShared *state;
static DWORD WINAPI thread_marker(LPVOID ignored) {
    (void)ignored;
    DWORD result=lab_env_marker("thread_marker");
    if(!result) InterlockedIncrement(&state->markers);
    return result;
}
static VOID CALLBACK apc_marker(ULONG_PTR ignored) {
    (void)ignored;
    if(!lab_env_marker("apc_marker")) InterlockedIncrement(&state->markers);
}

int wmain(int argc, WCHAR **argv) {
    if(argc!=6) {
        fwprintf(stderr,L"Usage: NT230_target.exe RUN SCENARIO idle|alertable|nonalertable|selfdll|selfapc OUTPUT_DIR SECONDS\n");
        return 2;
    }
    if(!lab_token(argv[1]) || !lab_token(argv[2]) || !lab_gate()) return 2;
    const WCHAR *mode=argv[3];
    if(wcscmp(mode,L"idle") && wcscmp(mode,L"alertable") && wcscmp(mode,L"nonalertable") &&
       wcscmp(mode,L"selfdll") && wcscmp(mode,L"selfapc")) return 2;
    WCHAR *end=NULL; unsigned long seconds=wcstoul(argv[5],&end,10);
    if(!end || *end || seconds<2 || seconds>3600) return 2;
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    WCHAR out[LAB_PATH],name[128];
    DWORD outlen=GetFullPathNameW(argv[4],LAB_PATH,out,NULL);
    if(!outlen || outlen>=LAB_PATH) return 2;
    DWORD attrs=GetFileAttributesW(out);
    if(attrs==INVALID_FILE_ATTRIBUTES || !(attrs&FILE_ATTRIBUTE_DIRECTORY)) return 2;
    lab_map_name(name,argv[1]);
    HANDLE mapping=CreateFileMappingW(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,sizeof(LabShared),name);
    if(!mapping || GetLastError()==ERROR_ALREADY_EXISTS) {if(mapping) CloseHandle(mapping);return 3;}
    state=(LabShared*)MapViewOfFile(mapping,FILE_MAP_ALL_ACCESS,0,0,sizeof(LabShared));
    if(!state) {CloseHandle(mapping);return 3;}
    ZeroMemory(state,sizeof(*state));
    state->version=LAB_VERSION;state->pid=GetCurrentProcessId();state->tid=GetCurrentThreadId();
    wcscpy(state->run,argv[1]);wcscpy(state->scenario,argv[2]);wcscpy(state->output,out);
    GetModuleFileNameW(NULL,state->image,LAB_PATH);
    if(!lab_sibling(L"NT230_marker.dll",state->dll)) return 3;
    state->marker_fn=(ULONGLONG)(uintptr_t)thread_marker;
    state->apc_fn=(ULONGLONG)(uintptr_t)apc_marker;
    state->load_fn=(ULONGLONG)(uintptr_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"LoadLibraryW");
    state->free_fn=(ULONGLONG)(uintptr_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"FreeLibrary");
    SetEnvironmentVariableW(L"NT230_OUTPUT",out);SetEnvironmentVariableW(L"NT230_RUN",argv[1]);
    SetEnvironmentVariableW(L"NT230_SCENARIO",argv[2]);
    char dllpath[LAB_PATH*8];lab_json_wide(state->dll,dllpath,sizeof(dllpath));
    InterlockedExchange(&state->ready,1);
    if(!lab_log(out,L"target.jsonl",argv[1],argv[2],"ready",
        ",\"mode\":\"%ls\",\"architecture\":\"x64\",\"marker_address\":\"0x%llx\",\"apc_address\":\"0x%llx\",\"dll_path\":\"%s\"",
        mode,state->marker_fn,state->apc_fn,dllpath)) return 4;
    wprintf(L"READY run=%ls PID=%lu TID=%lu mode=%ls\n",argv[1],state->pid,state->tid,mode);fflush(stdout);
    int result=0;
    if(!wcscmp(mode,L"selfdll")) {
        HMODULE dll=LoadLibraryW(state->dll);
        lab_log(out,L"target.jsonl",argv[1],argv[2],"self_dll_load",",\"base\":\"0x%llx\",\"win32_error\":%lu",
                (ULONGLONG)(uintptr_t)dll,dll?0:GetLastError());
        if(dll) {
            typedef DWORD (WINAPI *Marker)(LPVOID);
            Marker marker=(Marker)(uintptr_t)GetProcAddress(dll,"Nt230DllMarker");
            if(!marker || marker(NULL)!=0) result=5;
            BOOL freed=FreeLibrary(dll);
            lab_log(out,L"target.jsonl",argv[1],argv[2],"self_dll_unload",",\"ok\":%s",freed?"true":"false");
        } else result=5;
    }
    if(!wcscmp(mode,L"selfapc")) {
        DWORD queued=QueueUserAPC(apc_marker,GetCurrentThread(),0);
        lab_log(out,L"target.jsonl",argv[1],argv[2],"self_apc_queue",",\"queued\":%s",queued?"true":"false");
        if(!queued) result=5;
    }
    BOOL alertable=!wcscmp(mode,L"alertable") || !wcscmp(mode,L"selfapc");
    ULONGLONG deadline=GetTickCount64()+seconds*1000ULL;
    while(GetTickCount64()<deadline) SleepEx(25,alertable);
    InterlockedExchange(&state->ready,0);
    lab_log(out,L"target.jsonl",argv[1],argv[2],"exit",",\"thread_apc_marker_count\":%ld,\"result\":%d",state->markers,result);
    /* Queued APC code is deliberately retained by injector until this process exits. */
    UnmapViewOfFile(state);CloseHandle(mapping);
    return result;
}
