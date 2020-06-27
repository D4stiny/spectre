/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "CreateThreadHook.h"

PPROCESS_QUEUE CreateThreadHook::ProcessQueue;

/**
    Enable the thread notification routine.
    @param Queue - The queue to use for new processes.
    @param Status - The status of initialization.
*/
CreateThreadHook::CreateThreadHook (
    _In_ PPROCESS_QUEUE Queue,
    _Inout_ PNTSTATUS Status
    )
{
    CreateThreadHook::ProcessQueue = Queue;
	//
	// Update the queue used by the Utilities class.
	//
	Utilities::ProcessQueue = Queue;
    //
    // Register for the notify routine.
    //
    *Status = PsSetCreateThreadNotifyRoutine(CreateThreadHook::ThreadNotifyRoutine);
    if (NT_SUCCESS(*Status) == FALSE)
    {
        DBGPRINT("CreateThreadHook!CreateThreadHook: Failed to create thread notify routine with status 0x%X.", *Status);
    }
}

/**
	Retrieve the full image file name for a process.
	@param ProcessId - The process to get the name of.
	@param ProcessImageFileName - PUNICODE_STRING to fill with the image file name of the process.
*/
NTSTATUS
CreateThreadHook::GetProcessImageFileName (
	_In_ HANDLE ProcessId,
	_Inout_ PUNICODE_STRING* ImageFileName
	)
{
	NTSTATUS status;
	PEPROCESS processObject;
	HANDLE processHandle;
	ULONG returnLength;

	processHandle = NULL;
	*ImageFileName = NULL;
	returnLength = 0;

	//
	// Before we can open a handle to the process, we need its PEPROCESS object.
	//
	status = PsLookupProcessByProcessId(ProcessId, &processObject);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("CreateThreadHook!GetProcessImageFileName: Failed to find process object with status 0x%X.", status);
		goto Exit;
	}

	//
	// Open a handle to the process.
	//
	status = ObOpenObjectByPointer(processObject, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, GENERIC_ALL, *PsProcessType, KernelMode, &processHandle);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("CreateThreadHook!GetProcessImageFileName: Failed to open handle to process with status 0x%X.", status);
		goto Exit;
	}

	//
	// Query for the size of the UNICODE_STRING.
	//
	status = ZwQueryInformationProcess(processHandle, ProcessImageFileName, NULL, 0, &returnLength);
	if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW)
	{
		DBGPRINT("CreateThreadHook!GetProcessImageFileName: Failed to query size of process ImageFileName with status 0x%X.", status);
		goto Exit;
	}

	//
	// Allocate the necessary space.
	//
	*ImageFileName = RCAST<PUNICODE_STRING>(ExAllocatePoolWithTag(PagedPool, returnLength, IMAGE_NAME_TAG));
	if (*ImageFileName == NULL)
	{
		DBGPRINT("CreateThreadHook!GetProcessImageFileName: Failed to allocate space for process ImageFileName.");
		goto Exit;
	}

	//
	// Query the image file name.
	//
	status = ZwQueryInformationProcess(processHandle, ProcessImageFileName, *ImageFileName, returnLength, &returnLength);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("CreateThreadHook!GetProcessImageFileName: Failed to query process ImageFileName with status 0x%X.", status);
		goto Exit;
	}
Exit:
	if (processHandle)
	{
		ZwClose(processHandle);
	}
	if (NT_SUCCESS(status) == FALSE && *ImageFileName)
	{
		ExFreePoolWithTag(*ImageFileName, IMAGE_NAME_TAG);
		*ImageFileName = NULL;
	}
	return status;
}

/**
    Notify routine used for starting requested processes.
    This is much better than the alternative of starting a process from
    a system thread.
    @param Process - The EPROCESS structure of the new/terminating process.
    @param ProcessId - The new child's process ID.
    @param CreateInfo - Information about the process being created.
*/
VOID
CreateThreadHook::ThreadNotifyRoutine (
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
	)
{
	NTSTATUS status;
	PPROCESS_QUEUE_INFO queueInfo;
	PUNICODE_STRING parentProcessName;
	WCHAR tempBuffer[MAX_PATH];
	HANDLE pipeReadHandle;
	HANDLE pipeWriteHandle;

	IO_STATUS_BLOCK statusBlock;
	HANDLE readEvent;
	OBJECT_ATTRIBUTES readEventAttributes;
	UNICODE_STRING readEventName;
	LARGE_INTEGER eventTimeout;

	ULONG pendingBytes;

	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ThreadId);
	UNREFERENCED_PARAMETER(Create);

	memset(&statusBlock, 0, sizeof(IO_STATUS_BLOCK));

	parentProcessName = NULL;
	pipeReadHandle = NULL;
	pipeWriteHandle = NULL;
	readEvent = NULL;
	queueInfo = NULL;
	status = STATUS_SUCCESS;

	RtlInitUnicodeString(&readEventName, NULL);

	//
	// Relative time is negative.
	//
	eventTimeout.QuadPart = -MILLISECONDS_TO_SYSTEMTIME(2000);

	//
	// If we have no queued processes, just ignore.
	//
	if (CreateThreadHook::ProcessQueue->IsQueueEmpty())
	{
		goto Exit;
	}

	//
	// Retrieve the parent process name.
	//
	status = CreateThreadHook::GetProcessImageFileName(PsGetCurrentProcessId(), &parentProcessName);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("CreateThreadHook!CreateProcessNotifyRoutine: Failed to retrieve the parent processes' name.");
		goto Exit;
	}

	NT_ASSERT(parentProcessName);

	//
	// Sanity check.
	//
	if (parentProcessName == NULL || parentProcessName->Buffer == NULL)
	{
		DBGPRINT("CreateThreadHook!CreateProcessNotifyRoutine: Failed to retrieve the parent processes' name, buffer was NULL.");
		goto Exit;
	}

	//
	// Make sure our temporary buffer will have enough space.
	//
	if (parentProcessName->Length > (MAX_PATH - 1))
	{
		DBGPRINT("CreateThreadHook!CreateProcessNotifyRoutine: Failed to retrieve the parent processes' name, buffer was too large with size %i.", parentProcessName->Length);
		goto Exit;
	}

	//
	// Copy the process name string.
	//
	memset(tempBuffer, 0, sizeof(tempBuffer));
	memcpy_s(tempBuffer, sizeof(tempBuffer), parentProcessName->Buffer, parentProcessName->Length);

	//
	// Search for the target dispatcher name.
	//
	if (wcsstr(tempBuffer, PROCESS_DISPATCHER_NAME) == NULL)
	{
		goto Exit;
	}
	DBGPRINT("CreateThreadHook!CreateProcessNotifyRoutine: Thread detected.");

	InitializeObjectAttributes(&readEventAttributes, &readEventName, 0, NULL, NULL);

	//
	// Create pipes to receive the output of the command prompt.
	//
	status = Utilities::CreatePipe(&pipeReadHandle, &pipeWriteHandle);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("CreateThreadHook!ThreadNotifyRoutine: Failed to create pipes with status 0x%X.", status);
		goto Exit;
	}

	DBGPRINT("CreateThreadHook!ThreadNotifyRoutine: ReadPipe = 0x%X, WritePipe = 0x%X.", pipeReadHandle, pipeWriteHandle);

	//
	// Create the event to read asynchronously from the pipe.
	//
	status = ZwCreateEvent(&readEvent, EVENT_ALL_ACCESS, &readEventAttributes, NotificationEvent, FALSE);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("CreateThreadHook!ThreadNotifyRoutine: Failed to create read event with status 0x%X.", status);
		goto Exit;
	}

	//
	// Grab the latest process.
	//
	queueInfo = CreateThreadHook::ProcessQueue->PopProcess();
	if (queueInfo == NULL)
	{
		goto Exit;
	}

	//
	// Start the process.
	//
	status = Utilities::StartProcess(&queueInfo->CurrentDirectory, &queueInfo->ProcessImageName, &queueInfo->Arguments, queueInfo->Timeout, &pipeWriteHandle);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("CreateThreadHook!ThreadNotifyRoutine: Failed to start process with status 0x%X.", status);
		goto Exit;
	}

	//
	// Check how many bytes there are to read.
	//
	status = Utilities::PeekNamedPipe(pipeReadHandle, &pendingBytes);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("CreateThreadHook!ThreadNotifyRoutine: Failed to obtain pending bytes with status 0x%X.", status);
		goto Exit;
	}

	//
	// If there are no bytes to read, exit.
	//
	if (pendingBytes == 0)
	{
		DBGPRINT("CreateThreadHook!ThreadNotifyRoutine: There are no bytes to read.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}

	DBGPRINT("CreateThreadHook!ThreadNotifyRoutine: pendingBytes = %i", pendingBytes);

	//
	// Read the output.
	//
	status = ZwReadFile(pipeReadHandle, readEvent, NULL, NULL, &statusBlock, queueInfo->OutputBuffer, *queueInfo->OutputBufferSize, NULL, NULL);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("CreateThreadHook!ThreadNotifyRoutine: Failed to read from pipe with status 0x%X.", status);
		goto Exit;
	}

	//
	// Update the output buffer size to reflect the number of bytes returned.
	//
	*queueInfo->OutputBufferSize = SCAST<ULONG>(statusBlock.Information);
Exit:
	if(queueInfo)
	{
		queueInfo->ResultStatus = status;
		if (NT_SUCCESS(status) == FALSE)
		{
			//
			// Set the output to 0 for failure.
			//
			*queueInfo->OutputBufferSize = 0;
		}
		//
		// Signal the completion event.
		//
		status = ZwSetEvent(queueInfo->CompletionEvent, NULL);
		if (NT_SUCCESS(status) == FALSE)
		{
			DBGPRINT("CreateThreadHook!ThreadNotifyRoutine: Failed to signal completion event with status 0x%X.", status);
		}
	}
	if (parentProcessName)
	{
		ExFreePoolWithTag(parentProcessName, IMAGE_NAME_TAG);
	}
	if (pipeReadHandle)
	{
		ZwClose(pipeReadHandle);
	}
	if (pipeWriteHandle)
	{
		ZwClose(pipeWriteHandle);
	}
	if (readEvent)
	{
		ZwClose(readEvent);
	}
}