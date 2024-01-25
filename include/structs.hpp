#ifndef STRUCTS_HPP
#define STRUCTS_HPP

#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

#endif //STRUCTS_HPP
