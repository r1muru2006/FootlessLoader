#ifndef NT230_LAB_H
#define NT230_LAB_H
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>
#include <string.h>

#ifndef _WIN64
#error This lab supports native Windows x64 only; build all components as x64.
#endif
#define LAB_VERSION 1
#define LAB_PATH 1024
typedef struct {
    DWORD version, pid, tid;
    volatile LONG ready, markers, attempted;
    ULONGLONG marker_fn, apc_fn, load_fn, free_fn;
    WCHAR image[LAB_PATH], dll[LAB_PATH], output[LAB_PATH];
    WCHAR run[80], scenario[80];
} LabShared;

static inline BOOL lab_token(const WCHAR *s) {
    size_t n = wcslen(s);
    if (!n || n >= 80) return FALSE;
    for (size_t i=0; i<n; ++i)
        if (!((s[i]>=L'a' && s[i]<=L'z') || (s[i]>=L'A' && s[i]<=L'Z') ||
              (s[i]>=L'0' && s[i]<=L'9') || s[i]==L'_' || s[i]==L'-')) return FALSE;
    return TRUE;
}
static inline BOOL lab_gate(void) {
    WCHAR snapshot[256];
    DWORD n=GetEnvironmentVariableW(L"NT230_VM_SNAPSHOT",snapshot,256);
    if (!n || n>=256) {
        fwprintf(stderr,L"Lab requires NT230_VM_SNAPSHOT naming a snapshot in your test VM. See README.md.\n");
        return FALSE;
    }
    return TRUE;
}
static inline void lab_map_name(WCHAR *dest, const WCHAR *run) {
    swprintf(dest,128,L"Local\\NT230_InjectionLab_%ls",run);
}
static inline BOOL lab_sibling(const WCHAR *name, WCHAR *dest) {
    if (!GetModuleFileNameW(NULL,dest,LAB_PATH)) return FALSE;
    WCHAR *slash=wcsrchr(dest,L'\\');
    if (!slash || (size_t)(slash-dest)+1+wcslen(name)>=LAB_PATH) return FALSE;
    wcscpy(slash+1,name);
    return TRUE;
}
/* Escape paths/labels before embedding them in JSON. */
static inline void lab_json_wide(const WCHAR *s, char *dest, size_t cap) {
    char utf8[LAB_PATH*4];
    int n=WideCharToMultiByte(CP_UTF8,0,s,-1,utf8,sizeof(utf8),NULL,NULL);
    size_t j=0;
    if (!n) { if(cap) dest[0]=0; return; }
    for (int i=0;i<n-1 && j+7<cap;i++) {
        unsigned char c=(unsigned char)utf8[i];
        if(c=='"' || c=='\\') {dest[j++]='\\';dest[j++]=(char)c;}
        else if(c<32) {snprintf(dest+j,cap-j,"\\u%04x",c);j+=6;}
        else dest[j++]=(char)c;
    }
    dest[j]=0;
}
static inline BOOL lab_log(const WCHAR *dir, const WCHAR *file, const WCHAR *run,
                          const WCHAR *scenario, const char *event, const char *fmt, ...) {
    WCHAR path[LAB_PATH]; char r[512],s[512],detail[12000],line[15000];
    SYSTEMTIME t; DWORD written=0; va_list args;
    if(wcslen(dir)+wcslen(file)+2>=LAB_PATH) return FALSE;
    swprintf(path,LAB_PATH,L"%ls\\%ls",dir,file);
    lab_json_wide(run,r,sizeof(r));lab_json_wide(scenario,s,sizeof(s));
    va_start(args,fmt);vsnprintf(detail,sizeof(detail),fmt,args);va_end(args);
    GetSystemTime(&t);
    int n=snprintf(line,sizeof(line),
        "{\"utc\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\",\"tick_ms\":%llu,"
        "\"run_id\":\"%s\",\"scenario_id\":\"%s\",\"pid\":%lu,\"tid\":%lu,\"event\":\"%s\"%s}\n",
        t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond,t.wMilliseconds,
        (unsigned long long)GetTickCount64(),r,s,GetCurrentProcessId(),GetCurrentThreadId(),event,detail);
    if(n<0 || n>=(int)sizeof(line)) return FALSE;
    HANDLE f=CreateFileW(path,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(f==INVALID_HANDLE_VALUE) return FALSE;
    BOOL ok=WriteFile(f,line,(DWORD)n,&written,NULL) && written==(DWORD)n;
    if(ok) ok=FlushFileBuffers(f);
    DWORD write_error=ok?0:GetLastError();
    CloseHandle(f);
    if(!ok) fprintf(stderr,"Log write failed: %lu\n",write_error);
    return ok;
}
static inline DWORD lab_env_marker(const char *kind) {
    WCHAR dir[LAB_PATH],run[80],scenario[80];
    if(!GetEnvironmentVariableW(L"NT230_OUTPUT",dir,LAB_PATH) ||
       !GetEnvironmentVariableW(L"NT230_RUN",run,80) ||
       !GetEnvironmentVariableW(L"NT230_SCENARIO",scenario,80)) return 1;
    return lab_log(dir,L"marker.jsonl",run,scenario,"marker",",\"kind\":\"%s\"",kind)?0:2;
}
#endif
