/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "Utils.h"

//
// Thanks @0xNemi for the idea of resolving unexported ZwXx functions
// by using the system call number from ntdll.dll and searching for it
// in ntoskrnl's executable sections.
//
typedef class NtFunctionResolver
{
    //
    // Buffer containing the file contents of ntdll.dll.
    //
    PVOID NtdllBuffer;
    //
    // Size of NtdllBuffer.
    //
    ULONG NtdllBufferSize;
    //
    // Information about the ntoskrnl module. Obtained on initialization for optimization purposes.
    //
    RTL_PROCESS_MODULE_INFORMATION NtoskrnlModule;
public:
    NtFunctionResolver (
        VOID
        );

    NTSTATUS LoadNtdllModule (
        VOID
        );

    LONG FindExportSyscall (
        _In_ CHAR* NtFunctionName
        );

    PVOID FindSyscallZwFunction (
        _In_ CONST LONG SyscallNumber
        );
} NT_FUNCTION_RESOLVER, *PNT_FUNCTION_RESOLVER;

#define NTDLL_MODULE_TAG DEFINE_TAG('mNpS')
#define NT_FUNCTION_RESOLVER_TAG DEFINE_TAG('rNpS')