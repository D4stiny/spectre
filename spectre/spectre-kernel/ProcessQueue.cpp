/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "ProcessQueue.h"

/**
	Initialize basic members of the ProcessQueue class.
*/
ProcessQueue::ProcessQueue()
{
	this->processLock = RCAST<PKSPIN_LOCK>(ExAllocatePoolWithTag(NonPagedPool, sizeof(KSPIN_LOCK), PROCESS_LOCK_TAG));
	NT_ASSERT(this->processLock);
	KeInitializeSpinLock(this->processLock);
	InitializeListHead(RCAST<PLIST_ENTRY>(&this->processHead));
}

/**
	Push a process to the queue.
	@param Process - The process to push.
	@return Whether or not pushing the process was successful.
*/
PPROCESS_QUEUE_INFO
ProcessQueue::PushProcess (
	_In_ PPROCESS_QUEUE_INFO Process
	)
{
	PPROCESS_QUEUE_INFO newProcess;

	//
	// Allocate space for the new process and copy the details.
	//
	newProcess = RCAST<PPROCESS_QUEUE_INFO>(ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_QUEUE_INFO), PROCESS_QUEUE_ENTRY_TAG));
	if (newProcess == NULL)
	{
		DBGPRINT("ProcessQueue!PushProcess: Failed to allocate space for the new process.");
		return NULL;
	}
	memset(newProcess, 0, sizeof(PROCESS_QUEUE_INFO));
	memcpy(newProcess, Process, sizeof(PROCESS_QUEUE_INFO));

	//
	// Queue the process.
	//
	ExInterlockedInsertTailList(RCAST<PLIST_ENTRY>(&this->processHead), RCAST<PLIST_ENTRY>(newProcess), this->processLock);

	return newProcess;
}

/**
	Check if the queue of processes is empty.
	WARNING: Potential for a race condition, use with caution.
	@return Whether or not the process queue is empty.
*/
BOOLEAN
ProcessQueue::IsQueueEmpty (
	VOID
	)
{
	BOOLEAN empty;
	KIRQL oldIrql;

	ExAcquireSpinLock(this->processLock, &oldIrql);
	empty = IsListEmpty(RCAST<PLIST_ENTRY>(&this->processHead));
	ExReleaseSpinLock(this->processLock, oldIrql);

	return empty;
}

/**
	Pop a process from the queue of processes. Follows FI-FO.
	@return The first in queued process.
*/
PPROCESS_QUEUE_INFO
ProcessQueue::PopProcess (
	VOID
	)
{
	return RCAST<PPROCESS_QUEUE_INFO>(ExInterlockedRemoveHeadList(RCAST<PLIST_ENTRY>(&this->processHead), this->processLock));
}

/**
	Free a previously pop'd process.
	@param Process - The process to free.
*/
VOID
ProcessQueue::FreeProcess (
	_In_ PPROCESS_QUEUE_INFO Process
	)
{
	ExFreePoolWithTag(Process, PROCESS_QUEUE_ENTRY_TAG);
}