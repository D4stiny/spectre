/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "Utils.h"

PPROCESS_QUEUE Utilities::ProcessQueue;

/**
	Determine the address and size of a kernel module's next executable section.
	WARNING: Unsafe with modules that have pageable sections.
	@param ImageBase - Image base of the kernel module.
	@param ExecSectionBase - Caller-allocated variable to indicate the first section to start searching from and store the next executable section base.
	@param ExecSectionSize - Caller-allocated variable to store the next executable section size.
	@return Status of the section search.
*/
NTSTATUS
Utilities::FindNextExecSection (
	_In_ PVOID ImageBase,
	_Inout_ PVOID* ExecSectionBase,
	_Inout_ SIZE_T* ExecSectionSize
	)
{
	NTSTATUS status;
	PIMAGE_DOS_HEADER driverDosHeader;
	PIMAGE_NT_HEADERS_C driverNtHeader;
	PIMAGE_SECTION_HEADER driverSectionHeader;
	BOOLEAN foundStartSectionBase;
	ULONG i;
	PVOID currentSectionBase;

	status = STATUS_SUCCESS;
	*ExecSectionSize = 0;
	foundStartSectionBase = FALSE;

	//
	// Check if a starting section was specified. If not, return the first section.
	//
	if (*ExecSectionBase == NULL)
	{
		foundStartSectionBase = TRUE;
	}

	driverDosHeader = RCAST<PIMAGE_DOS_HEADER>(ImageBase);
	if (driverDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		DBGPRINT("Utilities!FindModuleTextSection: The image has an invalid DOS Header Magic value.");
		status = STATUS_INVALID_ADDRESS;
		goto Exit;
	}

	driverNtHeader = RCAST<PIMAGE_NT_HEADERS_C>(RCAST<ULONG_PTR>(driverDosHeader) + driverDosHeader->e_lfanew);
	if (driverNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		DBGPRINT("Utilities!FindModuleTextSection: The image has an invalid NT Header Magic value.");
		status = STATUS_INVALID_ADDRESS;
		goto Exit;
	}

	driverSectionHeader = IMAGE_FIRST_SECTION(driverNtHeader);

	//
	// Enumerate each section of the driver for the ".text" section.
	//
	for (i = 0; i < driverNtHeader->FileHeader.NumberOfSections; i++)
	{
		currentSectionBase = RCAST<PVOID>(RCAST<ULONG_PTR>(driverDosHeader) + driverSectionHeader[i].VirtualAddress);
		if (foundStartSectionBase == FALSE && currentSectionBase == *ExecSectionBase)
		{
			foundStartSectionBase = TRUE;
			continue;
		}
		else if (foundStartSectionBase && FlagOn(driverSectionHeader[i].Characteristics, IMAGE_SCN_MEM_EXECUTE))
		{
			*ExecSectionBase = currentSectionBase;
			*ExecSectionSize = driverSectionHeader[i].SizeOfRawData;
			break;
		}
	}
Exit:
	return status;
}

/**
	Search for a Pattern of bytes that match the Mask.
	@param Address - The address to begin the search at.
	@param Length - The number of bytes to compare.
	@param Pattern - The pattern to match.
	@param Mask - The mask to apply to the pattern.
	@return NULL if not found. Otherwise, a pointer to the first match.
*/
PVOID
Utilities::FindPattern (
	_In_ CONST PVOID Address,
	_In_ CONST SIZE_T Length,
	_In_ CONST CHAR* Pattern,
	_In_ CONST CHAR* Mask
	)
{
	for (auto i = 0; i < Length; i++)
		if (Utilities::CompareData(RCAST<CONST CHAR*>(RCAST<ULONG_PTR>(Address) + i), Pattern, Mask))
			return RCAST<PVOID>(RCAST<ULONG_PTR>(Address) + i);
	return NULL;
}

/**
	Compare data against a pattern and mask.
	@param Data - The data to compare.
	@param Pattern - The pattern to compare against.
	@param Mask - The mask to apply to the pattern.
	@return Whether or not the data fits the pattern and mask.
*/
BOOLEAN
Utilities::CompareData (
	_In_ CONST CHAR* Data,
	_In_ CONST CHAR* Pattern,
	_In_ CONST CHAR* Mask
	)
{
	for (; *Mask; ++Mask, ++Data, ++Pattern)
		if (*Mask == 'x' && *Data != *Pattern)
			return FALSE;
	return (*Mask) == 0;
}

/**
	Enumerate executable sections in ImpersonateDriver and find a "jmp rcx" gadget.
	If found, create a new thread at that gadget location, to spoof the start address of the thread.
	Set the first argument (rcx register) passed to the thread to be the actual thread function, which the gadget will jump to.
*/
BOOLEAN
Utilities::CreateHiddenThread (
	_In_ PVOID DriverBase,
	_In_ PVOID ThreadFunction
	)
{
	NTSTATUS status;
	HANDLE threadHandle;
	PVOID jmpRcxGadget;
	PVOID currentExecutableSection;
	SIZE_T currentExecutableSectionSize;

	jmpRcxGadget = NULL;
	currentExecutableSection = NULL;
	currentExecutableSectionSize = 0;

	//
	// Enumerate each executable of the ImpersonateDriver to look for a "jmp rcx" (0xFF, 0xE1) gadget.
	//
	while (NT_SUCCESS(Utilities::FindNextExecSection(DriverBase, &currentExecutableSection, &currentExecutableSectionSize)) && jmpRcxGadget == NULL)
	{
		NT_ASSERT(currentExecutableSection);
		jmpRcxGadget = FindPattern(currentExecutableSection, currentExecutableSectionSize, "\xFF\xE1", "xx");
	}

	//
	// Check if we were able to find a gadget.
	//
	if (jmpRcxGadget == NULL)
	{
		DBGPRINT("Utilities!CreateHiddenThread: Failed to find a \"jmp rcx\" gadget in the driver.");
		return FALSE;
	}

	//
	// Create a system thread on the "jmp rcx" gadget with the actual thread function as the first argument (rcx register).
	//
	status = PsCreateSystemThread(&threadHandle, 0, NULL, 0, NULL, RCAST<PKSTART_ROUTINE>(jmpRcxGadget), ThreadFunction);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("Utilities!CreateHiddenThread: Failed to create system thread with status 0x%X.", status);
		return FALSE;
	}
	
	ZwClose(threadHandle);
	return TRUE;
}

/**
	Get the system module information for a module specified by the name ModuleName.
	@param ModuleName - The name of the target system module.
	@return The target system module information. Will be empty if not found.
*/
CONST RTL_PROCESS_MODULE_INFORMATION
Utilities::GetDriverModule (
	_In_ CONST CHAR* ModuleName
	)
{
	NTSTATUS status;
	RTL_PROCESS_MODULE_INFORMATION driverModuleInformation;
	RTL_PROCESS_MODULE_INFORMATION currentModule;
	PRTL_PROCESS_MODULES systemModuleList;
	ULONG neededSize;
	ULONG i;

	memset(&driverModuleInformation, 0, sizeof(driverModuleInformation));
	neededSize = 0;

	//
	// Query the bytes required to query system modules.
	//
	ZwQuerySystemInformation(SystemModuleInformation, &neededSize, 0, &neededSize);

	//
	// Allocate space for modules.
	//
	systemModuleList = RCAST<PRTL_PROCESS_MODULES>(ExAllocatePoolWithTag(NonPagedPoolNx, neededSize, SYSTEM_MODULE_INFO_TAG));
	if (systemModuleList == NULL)
	{
		DBGPRINT("Utilities!GetDriverModule: Failed to allocate space for system module list.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}

	//
	// Query the system modules.
 	//
	status = ZwQuerySystemInformation(SystemModuleInformation, systemModuleList, neededSize, NULL);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("Utilities!GetDriverModule: Failed to query the system module list with status 0x%X.", status);
		goto Exit;
	}

	//
	// Enumerate each system module for a match.
	//
	for (i = 0; i < systemModuleList->NumberOfModules; i++)
	{
		currentModule = systemModuleList->Modules[i];
		if(strstr(RCAST<CONST CHAR*>(currentModule.FullPathName), ModuleName) != NULL)
		{
			driverModuleInformation = currentModule;
			break;
		}
	}
Exit:
	if (NT_SUCCESS(status) == FALSE && systemModuleList)
	{
		ExFreePoolWithTag(systemModuleList, SYSTEM_MODULE_INFO_TAG);
	}
	return driverModuleInformation;
}

/**
	Reimplemented ZwCreateNamedPipeFile.
*/
NTSTATUS
ZwCreateNamedPipeFile (
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_ ULONG NamedPipeType,
	_In_ ULONG ReadMode,
	_In_ ULONG CompletionMode,
	_In_ ULONG MaxInstances,
	_In_ ULONG InBufferSize,
	_In_ ULONG OutBufferSize,
	_In_ PLARGE_INTEGER DefaultTimeout
	)
{
	NAMED_PIPE_CREATE_PARAMETERS namedPipeCreateParams;

	//
	// Fill out the create parameters.
	//
	namedPipeCreateParams.NamedPipeType = NamedPipeType;
	namedPipeCreateParams.ReadMode = ReadMode;
	namedPipeCreateParams.CompletionMode = CompletionMode;
	namedPipeCreateParams.MaximumInstances = MaxInstances;
	namedPipeCreateParams.InboundQuota = InBufferSize;
	namedPipeCreateParams.OutboundQuota = OutBufferSize;
	namedPipeCreateParams.TimeoutSpecified = FALSE;

	if (DefaultTimeout)
	{
		namedPipeCreateParams.DefaultTimeout = *DefaultTimeout;
		namedPipeCreateParams.TimeoutSpecified = TRUE;
	}
	
	//
	// Create the named pipe.
	//
	return IoCreateFile(FileHandle,
						DesiredAccess,
						ObjectAttributes,
						IoStatusBlock,
						NULL,
						0,
						ShareAccess,
						CreateDisposition,
						CreateOptions,
						NULL,
						0,
						CreateFileTypeNamedPipe,
						&namedPipeCreateParams,
						0);
}


/**
	Creates an unnamed pipe for reading/writing. Quite literally just reversed CreatePipe in kernelbase.dll.
	@param hReadPipe - Pointer to a HANDLE that will receive a READ handle to the new pipe.
	@param hWritePipe - Pointer to a HANDLE that will receive a WRITE handle to the new pipe.
	@return Status of creating the new pipe.
*/
NTSTATUS
Utilities::CreatePipe (
	_Inout_ PHANDLE hReadPipe,
	_Inout_ PHANDLE hWritePipe
	)
{
	NTSTATUS status;
	HANDLE namedPipeDirectory;
	OBJECT_ATTRIBUTES rootNamedPipeAttributes;
	UNICODE_STRING namedPipePath;
	IO_STATUS_BLOCK statusBlock;

	OBJECT_ATTRIBUTES newNamedPipeAttributes;
	HANDLE newPipeReadHandle;
	HANDLE newPipeWriteHandle;
	LARGE_INTEGER defaultTimeout;

	namedPipeDirectory = NULL;
	newPipeReadHandle = NULL;
	newPipeWriteHandle = NULL;
	defaultTimeout.QuadPart = -1200000000;
	*hReadPipe = NULL;
	*hWritePipe = NULL;

	RtlInitUnicodeString(&namedPipePath, L"\\Device\\NamedPipe\\");

	InitializeObjectAttributes(&rootNamedPipeAttributes, &namedPipePath, 0, NULL, NULL);
	
	//
	// Open the root NamedPipe directory.
	//
	status = ZwOpenFile(&namedPipeDirectory, GENERIC_READ | SYNCHRONIZE, &rootNamedPipeAttributes, &statusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("Utilities!CreatePipe: Failed to open root NamedPipe directory with status 0x%X.", status);
		goto Exit;
	}

	//
	// We are creating an unnamed pipe, so set the UNICODE_STRING buffer/length to NULL.
	//
	namedPipePath.Buffer = NULL;
	namedPipePath.Length = 0;

	//
	// For the new NamedPipe root directory, we pass the handle for the
	// root NamedPipe directory since we don't specify an object name.
	//
	InitializeObjectAttributes(&newNamedPipeAttributes, &namedPipePath, OBJ_CASE_INSENSITIVE | OBJ_INHERIT, namedPipeDirectory, NULL);

	//
	// Create the new pipe.
	//
	status = ZwCreateNamedPipeFile(&newPipeReadHandle,
								   GENERIC_READ | SYNCHRONIZE | FILE_WRITE_ATTRIBUTES,
								   &newNamedPipeAttributes,
								   &statusBlock,
								   FILE_SHARE_READ | FILE_SHARE_WRITE,
								   FILE_CREATE,
								   FILE_SYNCHRONOUS_IO_NONALERT,
								   FILE_PIPE_BYTE_STREAM_TYPE,
								   FILE_PIPE_BYTE_STREAM_MODE,
								   FILE_PIPE_QUEUE_OPERATION,
								   1,
								   0x1000,
								   0x1000,
								   &defaultTimeout);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("Utilities!CreatePipe: Failed to create pipe with status 0x%X.", status);
		goto Exit;
	}

	DBGPRINT("Utilities!CreatePipe: newPipeReadHandle = 0x%X.", newPipeReadHandle);

	//
	// This time the root directory is our handle to the new pipe.
	// We need to open a write handle next.
	//
	InitializeObjectAttributes(&newNamedPipeAttributes, &namedPipePath, OBJ_CASE_INSENSITIVE | OBJ_INHERIT, newPipeReadHandle, NULL);

	//
	// Open the write handle to the pipe.
	//
	status = ZwOpenFile(&newPipeWriteHandle,
						GENERIC_WRITE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
						&newNamedPipeAttributes,
						&statusBlock,
						FILE_SHARE_READ | FILE_SHARE_WRITE,
						FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("Utilities!CreatePipe: Failed to open pipe for writing with status 0x%X.", status);
		goto Exit;
	}

	//
	// Set the output handles to the new pipe handles.
	//
	*hReadPipe = newPipeReadHandle;
	*hWritePipe = newPipeWriteHandle;
Exit:
	if (namedPipeDirectory)
	{
		ZwClose(namedPipeDirectory);
	}
	if (NT_SUCCESS(status) == FALSE)
	{
		if (newPipeReadHandle)
		{
			ZwClose(newPipeReadHandle);
		}
		if (newPipeWriteHandle)
		{
			ZwClose(newPipeWriteHandle);
		}
	}
	return status;
}

/**
	Attempt to retrieve the number of pending bytes for a pipe.
	@param hNamedPipe - Handle to the pipe.
	@param AvailableReadBytes - The number of bytes pending on the pipe.
	@return If the query was successful, STATUS_SUCCESS.
*/
NTSTATUS
Utilities::PeekNamedPipe (
	_In_ HANDLE hNamedPipe,
	_In_ PULONG AvailableReadBytes
	)
{
	NTSTATUS status;
	FILE_PIPE_PEEK_BUFFER peekBuffer;
	IO_STATUS_BLOCK statusBlock;

	memset(&peekBuffer, 0, sizeof(peekBuffer));
	
	//
	// Send a peek request.
	//
	status = ZwFsControlFile(hNamedPipe,
							 NULL,
							 NULL,
							 NULL,
							 &statusBlock,
							 FSCTL_PIPE_PEEK,
							 NULL,
							 0,
							 &peekBuffer,
							 sizeof(peekBuffer));
	if (status == STATUS_PENDING)
	{
		status = ZwWaitForSingleObject(hNamedPipe, FALSE, NULL);
		if (NT_SUCCESS(status))
		{
			status = statusBlock.Status;
		}
	}

	//
	// Set the number of bytes available to read.
	//
	*AvailableReadBytes = peekBuffer.ReadDataAvailable;
	return status;
}

/**
	Convert a virtual address to a raw file offset.
	@param NtHeaders - The NT headers for the module.
	@param SectionHeader - The first section header of the module.
	@param VirtualAddress - The virtual address to convert.
	@return File offset for a virtual address, NULL if not found.
*/
ULONG
Utilities::RVA2Offset (
	_In_ PIMAGE_NT_HEADERS NtHeaders,
	_In_ PIMAGE_SECTION_HEADER SectionHeader,
	_In_ DWORD VirtualAddress
	)
{
	ULONG i;

	//
	// Enumerate every section to find the section that contains the EAT virtual address.
	//
	for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (VirtualAddress >= SectionHeader[i].VirtualAddress &&
			VirtualAddress < (SectionHeader[i].VirtualAddress + SectionHeader[i].SizeOfRawData))
		{
			return (VirtualAddress - SectionHeader[i].VirtualAddress) + SectionHeader[i].PointerToRawData;
		}
	}

	return NULL;
}

/**
	Find an exported function by its name.
	@param Module - Pointer to the module to search.
	@param ExportName - Name of the target export.
	@param MappedModule - Has the modules' sections been mapped to the appropriate virtual addresses?
	@return Pointer to the exported function, NULL if not found.
*/
PVOID
Utilities::FindExportByName (
	_In_ PVOID Module,
	_In_ CHAR* ExportName,
	_In_ BOOLEAN MappedModule
	)
{
	ULONG_PTR longModule;
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeaders;
	PIMAGE_SECTION_HEADER sectionHeader;
	ULONG eatDirectoryOffset;
	PIMAGE_EXPORT_DIRECTORY eatDirectory;
	DWORD* eatFunctions;
	WORD* eatOrdinals;
	DWORD* eatNames;
	ULONG i;
	CHAR* currentExportName;
	DWORD eatNameOffset;

	longModule = RCAST<ULONG64>(Module);
	sectionHeader = NULL;

	//
	// The dos header is just the module base.
	//
	dosHeader = RCAST<PIMAGE_DOS_HEADER>(Module);
	if (dosHeader->e_magic != 'ZM')
	{
		DBGPRINT("Utilities!FindExportByName: Module has invalid DOS header.");
		return NULL;
	}

	ntHeaders = RCAST<PIMAGE_NT_HEADERS>(longModule + dosHeader->e_lfanew);
	if (ntHeaders->Signature != 'EP')
	{
		DBGPRINT("Utilities!FindExportByName: Module has invalid NT header.");
		return NULL;
	}

	//
	// Get the EAT data directory.
	//
	eatDirectoryOffset = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (MappedModule == FALSE)
	{
		sectionHeader = RCAST<PIMAGE_SECTION_HEADER>(ntHeaders + 1);
		eatDirectoryOffset = RVA2Offset(ntHeaders, sectionHeader, eatDirectoryOffset);
	}
	eatDirectory = RCAST<PIMAGE_EXPORT_DIRECTORY>(longModule + eatDirectoryOffset);

	eatFunctions = RCAST<DWORD*>(longModule + eatDirectory->AddressOfFunctions);
	eatOrdinals = RCAST<WORD*>(longModule + eatDirectory->AddressOfNameOrdinals);
	eatNames = RCAST<DWORD*>(longModule + eatDirectory->AddressOfNames);

	if (MappedModule == FALSE)
	{
		eatFunctions = RCAST<DWORD*>(longModule + RVA2Offset(ntHeaders, sectionHeader, eatDirectory->AddressOfFunctions));
		eatOrdinals = RCAST<WORD*>(longModule + RVA2Offset(ntHeaders, sectionHeader, eatDirectory->AddressOfNameOrdinals));
		eatNames = RCAST<DWORD*>(longModule + RVA2Offset(ntHeaders, sectionHeader, eatDirectory->AddressOfNames));
	}

	//
	// Iterate over every export with a name.
	//
	for (i = 0; i < eatDirectory->NumberOfNames; i++)
	{
		eatNameOffset = eatNames[i];
		if (MappedModule == FALSE)
		{
			eatNameOffset = RVA2Offset(ntHeaders, sectionHeader, eatNameOffset);
		}
		currentExportName = RCAST<CHAR*>(longModule + eatNameOffset);

		//
		// Check if the export name matches our desired export.
		//
		if (strcmp(currentExportName, ExportName) == 0)
		{
			if (MappedModule == FALSE)
			{
				return RCAST<PVOID>(longModule + RVA2Offset(ntHeaders, sectionHeader, eatFunctions[eatOrdinals[i]]));
			}
			return RCAST<PVOID>(longModule + eatFunctions[eatOrdinals[i]]);
		}
	}

	return NULL;
}