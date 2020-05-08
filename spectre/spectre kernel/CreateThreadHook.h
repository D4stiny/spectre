/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "ProcessQueue.h"
#include "Utils.h"

//
// The name of the process we should search for.
// This is used to determine the parent process
// for new processes.
//
#define PROCESS_DISPATCHER_NAME L"svchost.exe"

typedef class CreateThreadHook
{
	static NTSTATUS GetProcessImageFileName (
		_In_ HANDLE ProcessId,
		_Inout_ PUNICODE_STRING* ImageFileName
		);
	static VOID ThreadNotifyRoutine (
		_In_ HANDLE ProcessId,
		_In_ HANDLE ThreadId,
		_In_ BOOLEAN Create
		);
	//
	// The queue of processes to start.
	//
	static PPROCESS_QUEUE ProcessQueue;
public:
	CreateThreadHook (
		_In_ PPROCESS_QUEUE Queue,
		_Inout_ PNTSTATUS Status
		);
} CREATE_THREAD_HOOK, *PCREATE_THREAD_HOOK;

#define CREATE_THREAD_HOOK_TAG DEFINE_TAG('hTpS')
#define IMAGE_NAME_TAG DEFINE_TAG('nIpS')