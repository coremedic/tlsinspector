#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <vector>
#include <cstdio>

HANDLE* EnumThreads(IN DWORD pid, OUT int* threadCount) {
    std::vector<HANDLE> tmpHandles;
    BOOL   bResult         = FALSE;
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    if (hThreadSnapshot == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
        printf("[!] CreateToolhelp32Snapshot returned an invalid handle for thread\n");
#endif

        return NULL;
    }

    THREADENTRY32 te32 = {0};
    te32.dwSize = sizeof(THREADENTRY32);

    bResult = Thread32First(hThreadSnapshot, &te32);
    if (!bResult) {
#ifdef DEBUG
        printf("[!] Thread32First returned false\n");
#endif

        CloseHandle(hThreadSnapshot);
        return NULL;
    }

    while (bResult) {
        if (te32.th32OwnerProcessID == pid) {
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
            if (hThread) {
#ifdef DEBUG
                printf("[i] Inspecting thread [%lu] of process [%lu]\n", te32.th32ThreadID, te32.th32OwnerProcessID);
#endif

                tmpHandles.push_back(hThread);
            }
        }
        bResult = Thread32Next(hThreadSnapshot, &te32);
    }
    CloseHandle(hThreadSnapshot);

    HANDLE* phThreads = new HANDLE[tmpHandles.size()];
    *threadCount = static_cast<int>(tmpHandles.size());

    for (size_t i = 0; i < tmpHandles.size(); ++i) {
        phThreads[i] = tmpHandles[i];
    }
    return phThreads;
}

BOOL CheckTLSCallbackArray(IN HANDLE hProc, IN HANDLE hThread) {
    if (!hProc || !hThread) {
#ifdef DEBUG
        printf("[!] Process or Thread handle is NULL\n");
#endif

        return FALSE;
    }

    ULONG_PTR               uImageBase          = NULL,
                            uImageBaseBuffer    = NULL;
    PIMAGE_NT_HEADERS       pImgNtHdrs          = NULL;
    PIMAGE_DATA_DIRECTORY   pEntryTLSDataDir    = NULL;
    PIMAGE_TLS_CALLBACK     pImgTlsCallback     = NULL;
    CONTEXT                 ThreadContext       = {.ContextFlags = CONTEXT_ALL};
    BOOL                    bResult             = FALSE;

    if (!GetThreadContext(hThread, &ThreadContext)) {
#ifdef DEBUG
        printf("[!] GetThreadContext failed with error [%lu]\n", GetLastError());
#endif

        return FALSE;
    }

    size_t reserved3Offset = offsetof(PEB, Reserved3);
    size_t elementSize = sizeof(PEB::Reserved3[0]);
    size_t specificElementOffset = reserved3Offset + elementSize;
    PVOID specificElementAddress = (char*)(ThreadContext.Rdx) + specificElementOffset;
#ifdef DEBUG
    printf("[i] PPEB Address: 0x%p \n", (void*)ThreadContext.Rdx);
    printf("[i] Calculated Image Base Address To Be At: 0x%p \n", specificElementAddress);
#endif

    if (!ReadProcessMemory(hProc, specificElementAddress, &uImageBase, sizeof(PVOID), NULL)) {
#ifdef DEBUG
        printf("[!] ReadProcessMemory failed with error: [%lu]\n", GetLastError());
#endif

        return FALSE;
    }

    printf("[i] Image Base Address: 0x%p \n", (void*)uImageBase);

    if (!(uImageBaseBuffer = reinterpret_cast<ULONG_PTR>(LocalAlloc(LPTR, 0x1000)))) {
#ifdef DEBUG
        printf("[i] LocalAlloc failed with error: [%lu] \n", GetLastError());
#endif

        return FALSE;
    }

    if (!ReadProcessMemory(hProc, (PVOID)uImageBase, (LPVOID)uImageBaseBuffer, 0x1000, NULL)) {
#ifdef DEBUG
        printf("[!] ReadProcessMemory failed with error: [%lu]\n", GetLastError());
#endif

        goto _CLEAN_UP;
    }

    pImgNtHdrs = (PIMAGE_NT_HEADERS)(uImageBaseBuffer + ((PIMAGE_DOS_HEADER)uImageBaseBuffer)->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        goto _CLEAN_UP;
    }

    pEntryTLSDataDir = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!pEntryTLSDataDir->Size) {
#ifdef DEBUG
        printf("[!] Remote Process Does Not Have Any TLS Callback Function\n");
#endif

        goto _CLEAN_UP;
    }

    bResult = TRUE;
    printf("[i] Process seems to have a TLS callback function\n");

    _CLEAN_UP:
    LocalFree(reinterpret_cast<PVOID>(uImageBaseBuffer));
    return bResult;
}

int main() {
    HANDLE                      hProcSnapshot   = NULL;
    HANDLE*                     phThreads       = NULL;
    BOOL                        bResult         = FALSE;
    PROCESSENTRY32              pe32            = PROCESSENTRY32{};

    pe32.dwSize = sizeof(PROCESSENTRY32);

    hProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcSnapshot == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
        printf("[!] CreateToolhelp32Snapshot returned an invalid handle for process\n");
#endif

        goto _CLEAN_UP;
    }
    bResult = Process32First(hProcSnapshot, &pe32);
    if (!bResult) {
#ifdef DEBUG
        printf("[!] Process32First returned false\n");
#endif

        goto _CLEAN_UP;
    }

    while (bResult) {
#ifdef DEBUG
        printf("[i] Inspecting process [%lu]\n", pe32.th32ProcessID);
#endif

        if (hProcSnapshot) {
            int threadCount = 0;
            phThreads = EnumThreads(pe32.th32ProcessID, &threadCount);
            if (phThreads != NULL) {
                for (size_t i = 0; i < threadCount; ++i) {
                    BOOL b = FALSE;
                    b = CheckTLSCallbackArray(hProcSnapshot, phThreads[i]);
                    if (b) {
                        printf("[i] Process [%lu] seems to have a TLS callback function\n");
                    }
                }
            }
        } else {
#ifdef DEBUG
            printf("[i] No more processes to inspect\n");
#endif

            goto _CLEAN_UP;
        }
        delete[] phThreads;
        bResult = Process32Next(hProcSnapshot, &pe32);
    }

    _CLEAN_UP:
    if (hProcSnapshot) {
        CloseHandle(hProcSnapshot);
    }

    return 0;
}
