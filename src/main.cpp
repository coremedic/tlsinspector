#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cstdio>

#include "structs.hpp"

PVOID GetPebAddress(HANDLE ProcessHandle) {
    HMODULE hNtdll = LoadLibrary(TEXT("ntdll.dll"));
    if (hNtdll == NULL) {
        printf("Failed to load ntdll.dll\n");
        return NULL;
    }

    pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) {
        printf("Failed to get address of NtQueryInformationProcess\n");
        FreeLibrary(hNtdll);
        return NULL;
    }

    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (status != 0) {
        printf("NtQueryInformationProcess failed\n");
        FreeLibrary(hNtdll);
        return NULL;
    }

    FreeLibrary(hNtdll);
    return pbi.PebBaseAddress;
}

BOOL CheckTLSCallbackArray(IN HANDLE hProc, IN char procName[260]) {
    if (!hProc) {
#ifdef DEBUG
        printf("[!] Process or Thread handle is NULL\n");
#endif
        return FALSE;
    }

    PVOID pebAddress = GetPebAddress(hProc);
    if (pebAddress == NULL) {
#ifdef DEBUG
        printf("[!] Failed to get PEB address\n");
#endif
        return FALSE;
    }

    ULONG_PTR uImageBase = NULL;
    PVOID uImageBaseBuffer = NULL;
    PIMAGE_NT_HEADERS pImgNtHdrs = NULL;
    PIMAGE_DATA_DIRECTORY pEntryTLSDataDir = NULL;
    BOOL bResult = FALSE;

    if (!ReadProcessMemory(hProc, (PBYTE)pebAddress + 0x10, &uImageBase, sizeof(PVOID), NULL)) {
#ifdef DEBUG
        printf("[!] ReadProcessMemory failed to read the image base from PEB with error [%lu]\n", GetLastError());
#endif
        return FALSE;
    }

#ifdef DEBUG
    printf("[i] Image base address: 0x%p \n", (void*)uImageBase);
#endif

    uImageBaseBuffer = LocalAlloc(LPTR, 0x1000);
    if (!uImageBaseBuffer) {
#ifdef DEBUG
        printf("[i] LocalAlloc failed with error: [%lu] \n", GetLastError());
#endif
        return FALSE;
    }

    if (!ReadProcessMemory(hProc, (PVOID)uImageBase, uImageBaseBuffer, 0x1000, NULL)) {
#ifdef DEBUG
        printf("[!] ReadProcessMemory failed with error: [%lu]\n", GetLastError());
#endif
        goto _CLEAN_UP;
    }

    pImgNtHdrs = (PIMAGE_NT_HEADERS)((ULONG_PTR)uImageBaseBuffer + ((PIMAGE_DOS_HEADER)uImageBaseBuffer)->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
#ifdef DEBUG
        printf("[!] NT Headers signature mismatch\n");
#endif

        goto _CLEAN_UP;
    }

    pEntryTLSDataDir = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!pEntryTLSDataDir->Size) {
        goto _CLEAN_UP;
    }

    bResult = TRUE;

_CLEAN_UP:
    if (uImageBaseBuffer) {
        LocalFree(uImageBaseBuffer);
    }
    return bResult;
}


int main() {
    HANDLE                      hProcSnapshot   = NULL,
                                hProc           = NULL;
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
        printf("[i] Inspecting process [%s]\n", pe32.szExeFile);
#endif

        while (bResult) {
            hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProc) {
                BOOL b = FALSE;
                b = CheckTLSCallbackArray(hProc, pe32.szExeFile);
                if (b) {
                    printf("[i] Remote Process [%s] seems to have a TLS callback function\n", pe32.szExeFile);
                } else {
                    printf("[i] Remote Process [%s] does not have a TLS callback function\n", pe32.szExeFile);
                }
                CloseHandle(hProc);
            }
            bResult = Process32Next(hProcSnapshot, &pe32);
        }
    }

    _CLEAN_UP:
    if (hProcSnapshot) {
        CloseHandle(hProcSnapshot);
    }
    if (hProc) {
        CloseHandle(hProc);
    }

    return 0;
}
