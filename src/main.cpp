#include <windows.h>
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
