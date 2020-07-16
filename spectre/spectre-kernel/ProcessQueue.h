/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"

typedef struct ProcessQueueInfo
{
	LIST_ENTRY Entry;
	HANDLE CompletionEvent;				// The event to be signaled upon completion of the process. Alerted by the dispatcher.
	NTSTATUS ResultStatus;				// Whether or not the process was executed successfully. Populated by the dispatcher.
	UNICODE_STRING ProcessImageName;	// The path to the process to create.
	UNICODE_STRING CurrentDirectory;	// The current directory of the new process.
	UNICODE_STRING Arguments;			// The arguments to pass to the new process.
	LONG Timeout;						// The timeout (ms) before the process is forcefully killed if it has not already exited.
	BYTE* OutputBuffer;					// Pointer to the buffer that receives the output of the process.
	ULONG* OutputBufferSize;			// Size of the output buffer in bytes.
} PROCESS_QUEUE_INFO, *PPROCESS_QUEUE_INFO;

typedef class ProcessQueue
{
	PROCESS_QUEUE_INFO processHead;
	PKSPIN_LOCK processLock;

public:
	ProcessQueue();
	
	PPROCESS_QUEUE_INFO PushProcess (
		_In_ PPROCESS_QUEUE_INFO Process
		);

	PPROCESS_QUEUE_INFO PopProcess (
		VOID
		);

	BOOLEAN IsQueueEmpty (
		VOID
		);

	VOID FreeProcess (
		_In_ PPROCESS_QUEUE_INFO Process
		);
} PROCESS_QUEUE, *PPROCESS_QUEUE;

#define PROCESS_QUEUE_TAG DEFINE_TAG('qPpS')
#define PROCESS_LOCK_TAG DEFINE_TAG('lPpS')
#define PROCESS_QUEUE_ENTRY_TAG DEFINE_TAG('ePpS')