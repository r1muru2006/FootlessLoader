#include "../src/lab.h"
/* Host-side test only: validates serialization. No marker, remote memory, or thread APIs. */
int wmain(int argc,WCHAR **argv) {
    if(argc!=2) return 1;
    if(!lab_token(L"P01-run_123") || lab_token(L"bad/path") || lab_token(L"") || lab_token(L"quote\"")) return 2;
    char escaped[1024];
    lab_json_wide(L"C:\\lab\\quote\"\\dòng\n",escaped,sizeof(escaped));
    if(!strstr(escaped,"\\\\lab\\\\quote\\\"")) return 3;
    if(!lab_log(argv[1],L"contract.jsonl",L"contract",L"HOST_TEST","serialization_test",
        ",\"path\":\"%s\",\"pointer\":\"0x%llx\",\"value\":%llu",escaped,0x123456789abcdef0ULL,0x100000000ULL)) return 4;
    return 0;
}
