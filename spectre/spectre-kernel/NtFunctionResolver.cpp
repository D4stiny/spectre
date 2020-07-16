/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "NtFunctionResolver.h"

/**
    Initialize class members to NULL.
*/
NtFunctionResolver::NtFunctionResolver (
    VOID
    )
{
    this->NtdllBuffer = NULL;
    this->NtdllBufferSize = NULL;
    this->NtoskrnlModule = Utilities::GetDriverModule("ntoskrnl.exe");
}

/**
    Loads the ntdll module into memory.
    @return Whether or not loading the module succeeded.
*/
NTSTATUS
NtFunctionResolver::LoadNtdllModule (
    VOID
    )
{
    NTSTATUS status;
    HANDLE ntdllHandle;
    UNICODE_STRING ntdllPath;
    OBJECT_ATTRIBUTES ntdllAttributes;
    IO_STATUS_BLOCK statusBlock;
    FILE_STANDARD_INFORMATION fileStandardInfo;

    ntdllHandle = NULL;

    //
    // If we've already read the ntdll module, return that we succeeded.
    //
    if (NtdllBuffer)
    {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&ntdllPath, L"\\SystemRoot\\SYSTEM32\\NTDLL.dll");
    InitializeObjectAttributes(&ntdllAttributes, &ntdllPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    //
    // Open a HANDLE to the ntdll module.
    //
    status = ZwCreateFile(&ntdllHandle,
                          GENERIC_READ,
                          &ntdllAttributes,
                          &statusBlock,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          0,
                          FILE_OPEN,
                          FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL,
                          0);
    if (NT_SUCCESS(status) == FALSE)
    {
        DBGPRINT("NtFunctionResolver!LoadNtdllModule: Failed to open the ntdll module with status 0x%X.", status);
        goto Exit;
    }

    //
    // Query the size of the file by grabbing the standard info structure.
    //
    status = ZwQueryInformationFile(ntdllHandle, &statusBlock, &fileStandardInfo, sizeof(fileStandardInfo), FileStandardInformation);
    if (NT_SUCCESS(status) == FALSE)
    {
        DBGPRINT("NtFunctionResolver!LoadNtdllModule: Failed to query standard file information with status 0x%X.", status);
        goto Exit;
    }

    NtdllBufferSize = fileStandardInfo.EndOfFile.LowPart;
    DBGPRINT("NtFunctionResolver!LoadNtdllModule: Ntdll module has %lld bytes.", NtdllBufferSize);

    //
    // Allocate a buffer for the ntdll module.
    //
    NtdllBuffer = ExAllocatePoolWithTag(PagedPool, NtdllBufferSize, NTDLL_MODULE_TAG);
    if (NtdllBuffer == NULL)
    {
        DBGPRINT("NtFunctionResolver!LoadNtdllModule: Failed to allocate space for the ntdll module.");
        status = STATUS_NO_MEMORY;
        goto Exit;
    }
    memset(NtdllBuffer, 0, NtdllBufferSize);
    
    //
    // Read the ntdll module.
    //
    status = ZwReadFile(ntdllHandle, NULL, NULL, NULL, &statusBlock, NtdllBuffer, NtdllBufferSize, NULL, NULL);
    if (NT_SUCCESS(status) == FALSE)
    {
        DBGPRINT("NtFunctionResolver!LoadNtdllModule: Failed to read the ntdll module with status 0x%X.", status);
        goto Exit;
    }

    DBGPRINT("NtFunctionResolver!LoadNtdllModule: Read the ntdll module, NtdllBuffer = 0x%llx.", NtdllBuffer);
Exit:
    if (ntdllHandle)
    {
        ZwClose(ntdllHandle);
    }
    if (NT_SUCCESS(status) == FALSE)
    {
        if (NtdllBuffer)
        {
            ExFreePoolWithTag(NtdllBuffer, NTDLL_MODULE_TAG);
        }
        NtdllBufferSize = 0;
    }
    return status;
}

/**
    Find the DWORD system call number for an NtXx function.
    @param NtFunctionName - Name of the NtXx function to find the system call number of.
    @return The system call number, -1 if could not find.
*/
LONG
NtFunctionResolver::FindExportSyscall (
    _In_ CHAR* NtFunctionName
    )
{
    PVOID ntFunction;

    ntFunction = NULL;

    //
    // Find the address of the NtXx function.
    //
    ntFunction = Utilities::FindExportByName(NtdllBuffer, NtFunctionName, FALSE);
    if (ntFunction == NULL)
    {
        DBGPRINT("NtFunctionResolver!FindExportSyscall: Failed to find NtXx function.");
        return -1;
    }

    //
    // NtXx functions have the following assembly:
    // mov r10, rcx
    // mov eax, [system call number]
    // ...
    // The [system call number] ends up being at an offset of four.
    //
    return *RCAST<ULONG*>(RCAST<ULONG64>(ntFunction) + 4);
}

/**
    Find the ZwXx function pointer for a system call number.
    @param SyscallNumber - The system call number to find.
    @return Pointer to the ZwXx function, NULL if not found.
*/
PVOID
NtFunctionResolver::FindSyscallZwFunction (
    _In_ CONST LONG SyscallNumber
    )
{
    PVOID zwFunction;
    PVOID currentExecutableSection;
    SIZE_T currentExecutableSectionSize;
    BYTE zwFunctionBytes[] = {
        0x50,                           // push rax
        0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, [system call number]
        0xE9                            // jmp KiServiceInternal
    };
    CHAR* zwFunctionMask[sizeof(zwFunctionBytes) + 1];

    zwFunction = NULL;
    currentExecutableSection = NULL;
    currentExecutableSectionSize = 0;

    //
    // Update the bytes to use the system call number we're after.
    //
    *RCAST<ULONG*>(zwFunctionBytes + 2) = SyscallNumber;
    memset(zwFunctionMask, 'x', sizeof(zwFunctionBytes));
    zwFunctionMask[sizeof(zwFunctionBytes)] = '\0';

    //
    // Enumerate each executable section of the ntoskrnl driver to look for the ZwXx function.
    //
    while (NT_SUCCESS(Utilities::FindNextExecSection(this->NtoskrnlModule.ImageBase, &currentExecutableSection, &currentExecutableSectionSize)) && zwFunction == NULL)
    {
        zwFunction = Utilities::FindPattern(currentExecutableSection, currentExecutableSectionSize, RCAST<CONST CHAR*>(zwFunctionBytes), RCAST<CONST CHAR*>(zwFunctionMask));
    }

    //
    // On Windows 10 and 7, the offset of the signature is 0x13.
    //
    zwFunction = RCAST<PVOID>(RCAST<ULONG64>(zwFunction) - 0x13);

    return zwFunction;
}