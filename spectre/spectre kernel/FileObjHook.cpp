/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "FileObjHook.h"

//
// Static variables.
//
HOOK_TYPE FileObjHook::HookType;
PHOOK_DISPATCH FileObjHook::HookFunction;
PDRIVER_DISPATCH FileObjHook::OriginalDispatch[IRP_MJ_MAXIMUM_FUNCTION + 1];
PDEVICE_OBJECT FileObjHook::OriginalDeviceObject;
PDEVICE_OBJECT FileObjHook::FakeDeviceObject;

//
// Represents the current hook object needed by the dispatch function.
//
PFILE_OBJ_HOOK CurrentObjHook;

/**
	Initialize the FileObjHook class.
	@param TargetDeviceName - The name of the target device to hook.
	@param Type - Method of hooking.
	@param Hook - The function to redirect IRP_MJ_DEVICE_CONTROL to.
*/
FileObjHook::FileObjHook (
	_In_ PWCHAR TargetDeviceName,
	_In_ HOOK_TYPE Type,
	_In_ HOOK_DISPATCH Hook
	)
{
	ULONG hookCount;
	this->HookType = Type;
	this->HookFunction = Hook;
	CurrentObjHook = this;
	this->RescanThreadStarted = FALSE;

	//
	// Do not return until we get at least 1 hook.
	// This is required to start the rescan thread.
	//
	while (NT_SUCCESS(this->SearchAndHook(TargetDeviceName, &hookCount)) && hookCount == 0);
}

/**
	Check if a Handle in a Process is for a FILE_OBJECT.
	@param Process - The process the handle belongs to.
	@param Handle - The handle to check.
	@return Whether or not Handle is for a FILE_OBJECT.
*/
BOOLEAN
FileObjHook::IsHandleFile (
	_In_ PEPROCESS Process,
	_In_ HANDLE Handle
	)
{
	NTSTATUS status;
	BOOLEAN isFileObject;
	POBJECT_TYPE_INFORMATION objectType;
	ULONG objectTypeSize;
	KAPC_STATE apcState;

	isFileObject = FALSE;
	objectTypeSize = 0;

	//
	// Attach to the target process to query the handle's type.
	//
	KeStackAttachProcess(Process, &apcState);

	//
	// Query the appropriate size for the handle's type object.
	//
	ZwQueryObject(Handle, ObjectTypeInformation, NULL, 0, &objectTypeSize);

	//
	// Allocate the appropriate type information.
	//
	objectType = SCAST<POBJECT_TYPE_INFORMATION>(ExAllocatePoolWithTag(PagedPool, objectTypeSize, OBJECT_TYPE_TAG));
	if (objectType == NULL)
	{
		DBGPRINT("FileObjHook!IsHandleFile: Failed to allocate %i bytes for object type size.", objectTypeSize);
		goto Exit;
	}
	memset(objectType, 0, objectTypeSize);

	//
	// Query the object type.
	//
	status = ZwQueryObject(Handle, ObjectTypeInformation, objectType, objectTypeSize, &objectTypeSize);

	KeUnstackDetachProcess(&apcState);

	//
	// Check if the query was successful.
	//
	if (NT_SUCCESS(status) == FALSE)
	{
		//DBGPRINT("FileObjHook!IsHandleFile: Failed to query object type information with status 0x%X.", status);
		goto Exit;
	}

	//
	// Basic sanity check.
	//
	if (objectType->Name.Buffer == NULL)
	{
		goto Exit;
	}

	//
	// Check if the object type is a file object.
	//
	if (wcscmp(objectType->Name.Buffer, L"File") != 0)
	{
		goto Exit;
	}

	isFileObject = TRUE;
Exit:
	if (objectType)
	{
		ExFreePoolWithTag(objectType, OBJECT_TYPE_TAG);
	}
	return isFileObject;
}

/**
	Search for handles to a file object and hook objects that match TargetDeviceName.
	@param TargetDeviceName - The name of the target device to hook.
	@param HookCount - Caller-allocated variable to store the number of hooks placed by the function.
	@return Whether hooking was successful.
*/
BOOLEAN
FileObjHook::SearchAndHook (
	_In_ PWCHAR TargetDeviceName,
	_Inout_ ULONG* HookCount
	)
{
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION systemHandleInformation;
	ULONG systemHandleInformationSize;
	ULONG i;
	SYSTEM_HANDLE currentSystemHandle;
	PEPROCESS currentProcess;
	PFILE_OBJECT currentFileObject;
	POBJECT_HEADER_NAME_INFO fileDeviceName;

	UNREFERENCED_PARAMETER(HookType);
	UNREFERENCED_PARAMETER(HookFunction);

	this->ObjectsHooked = FALSE;
	systemHandleInformation = NULL;
	systemHandleInformationSize = 0x1000;
	*HookCount = 0;

	//
	// Until we have a large enough buffer for system handles, keep allocating a larger buffer.
	//
	do
	{
		//
		// Check if a buffer is allocated already. If so, allocate a new one double the size.
		//
		if (systemHandleInformation)
		{
			ExFreePoolWithTag(systemHandleInformation, HANDLE_INFO_TAG);
			systemHandleInformationSize *= 2;
		}

		//
		// Allocate the buffer to store system handles.
		//
		systemHandleInformation = RCAST<PSYSTEM_HANDLE_INFORMATION>(ExAllocatePoolWithTag(PagedPool, systemHandleInformationSize, HANDLE_INFO_TAG));
		if (systemHandleInformation == NULL)
		{
			DBGPRINT("FileObjHook!SearchAndHook: Failed to allocate %i bytes for system handle information.", systemHandleInformationSize);
			status = STATUS_NO_MEMORY;
			goto Exit;
		}
	} while ((status = ZwQuerySystemInformation(SystemHandleInformation, systemHandleInformation, systemHandleInformationSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH);
	
	//
	// Check if we queried system handles successfully.
	//
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("FileObjHook!SearchAndHook: Failed to query system handles with status 0x%X.", status);
		goto Exit;
	}

	for (i = 0; i < systemHandleInformation->HandleCount; i++)
	{
		currentSystemHandle = systemHandleInformation->Handles[i];

		//
		// Perform basic handle validation.
		//
		if (currentSystemHandle.Object == NULL ||
			NT_SUCCESS(PsLookupProcessByProcessId(RCAST<HANDLE>(currentSystemHandle.ProcessId), &currentProcess)) == FALSE)
		{
			continue;
		}

		//
		// Skip non-FILE_OBJECT handles.
		//
		if (IsHandleFile(currentProcess, RCAST<HANDLE>(currentSystemHandle.Handle)) == FALSE)
		{
			continue;
		}

		currentFileObject = SCAST<PFILE_OBJECT>(currentSystemHandle.Object);

		//
		// Sanity checks.
		//
		if (MmIsAddressValid(currentFileObject) == FALSE)
		{
			DBGPRINT("FileObjHook!SearchAndHook: FILE_OBJECT 0x%llx is invalid.", currentFileObject);
			continue;
		}
		if (currentFileObject->Size != sizeof(FILE_OBJECT))
		{
			DBGPRINT("FileObjHook!SearchAndHook: FILE_OBJECT 0x%llx has invalid size 0x%X.", currentFileObject, currentFileObject->Size);
			continue;
		}
		if (MmIsAddressValid(currentFileObject->DeviceObject) == FALSE)
		{
			DBGPRINT("FileObjHook!SearchAndHook: FILE_OBJECT 0x%llx DEVICE_OBJECT 0x%llx is invalid.", currentFileObject, currentFileObject->DeviceObject);
			continue;
		}
		//
		// TODO: Add a try/catch wrapper around the following to prevent race condition issues.
		// For now, do not change anything to observe issues that occur without a try/catch.
		//

		//
		// Query the name of the associated DEVICE_OBJECT.
		//
		fileDeviceName = SCAST<POBJECT_HEADER_NAME_INFO>(ObQueryNameInfo(currentFileObject->DeviceObject));

		//
		// Check if this is the device we're after.
		//
		if (MmIsAddressValid(fileDeviceName) && MmIsAddressValid(fileDeviceName->Name.Buffer) && currentFileObject->DeviceObject->DriverObject && wcscmp(fileDeviceName->Name.Buffer, TargetDeviceName) == 0)
		{
			//DBGPRINT("FileObjHook!SearchAndHook: Found a target device with name %wZ and device object 0x%llx, hooking.", fileDeviceName->Name, currentFileObject->DeviceObject);
			if (this->HookFileObject(currentFileObject) == FALSE)
			{
				DBGPRINT("FileObjHook!SearchAndHook: Failed to hook FILE_OBJECT 0x%llx.", currentFileObject);
				continue;
			}
			//DBGPRINT("FileObjHook!SearchAndHook: Hooked FILE_OBJECT 0x%llx.", currentFileObject);
			(*HookCount)++;

			//
			// Check if we need to start the rescan thread.
			//
			if (this->RescanThreadStarted == FALSE)
			{
				DBGPRINT("FileObjHook!SearchAndHook: Rescan thread not started, starting.");

				//
				// Start the hidden rescan thread.
				//
				if (Utilities::CreateHiddenThread(currentFileObject->DeviceObject->DriverObject, FileObjHook::RehookThread))
				{
					this->RescanThreadStarted = TRUE;
				}
			}
		}
	}
Exit:
	if (systemHandleInformation)
	{
		ExFreePoolWithTag(systemHandleInformation, HANDLE_INFO_TAG);
	}
	return NT_SUCCESS(status);
}

/**
	Generate a fake DRIVER_OBJECT that has IRP_MJ_DEVICE_CONTROL hooked.
	@param BaseDeviceObject - The device object to copy.
	@return Whether the objects were generated successfully.
*/
BOOLEAN
FileObjHook::GenerateHookObjects (
	_In_ PDEVICE_OBJECT BaseDeviceObject
	)
{
	NTSTATUS status;
	PDRIVER_OBJECT fakeDriverObject;
	OBJECT_ATTRIBUTES fakeDriverAttributes;
	CSHORT fakeDriverObjectSize;

	OBJECT_ATTRIBUTES fakeDeviceAttributes;
	POBJECT_HEADER_NAME_INFO realDeviceNameHeader;

	ULONG i;

	//
	// Generate the object attributes for the fake driver object.
	//
	InitializeObjectAttributes(&fakeDriverAttributes,
							   &BaseDeviceObject->DriverObject->DriverName,
							   OBJ_PERMANENT | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
							   NULL,
							   NULL);

	fakeDriverObjectSize = sizeof(DRIVER_OBJECT) + sizeof(EXTENDED_DRIVER_EXTENSION);

	//
	// These two object types must be valid.
	//
	NT_ASSERT(*IoDriverObjectType);
	NT_ASSERT(*IoDeviceObjectType);
	
	//
	// Create the fake driver object.
	//
	status = ObCreateObject(KernelMode, *IoDriverObjectType, &fakeDriverAttributes, KernelMode, NULL, fakeDriverObjectSize, 0, 0, RCAST<PVOID*>(&fakeDriverObject));
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("FileObjHook!GenerateHookObjects: Failed to create the fake driver object with status 0x%X.", status);
		goto Exit;
	}

	//
	// Copy the existing object.
	//
	memcpy(fakeDriverObject, BaseDeviceObject->DriverObject, fakeDriverObjectSize);

	realDeviceNameHeader = SCAST<POBJECT_HEADER_NAME_INFO>(ObQueryNameInfo(BaseDeviceObject));
	NT_ASSERT(realDeviceNameHeader);

	//
	// Generate the object attributes for the fake device object.
	//
	InitializeObjectAttributes(&fakeDeviceAttributes,
							   &realDeviceNameHeader->Name,
							   OBJ_KERNEL_HANDLE | OBJ_PERMANENT,
							   NULL,
							   BaseDeviceObject->SecurityDescriptor);

	//
	// Check if the original device is exclusive.
	//
	if (FlagOn(BaseDeviceObject->Flags, DO_EXCLUSIVE))
	{
		fakeDeviceAttributes.Attributes |= OBJ_EXCLUSIVE;
	}

	//
	// Create the fake device object.
	//
	status = ObCreateObject(KernelMode, *IoDeviceObjectType, &fakeDeviceAttributes, KernelMode, NULL, sizeof(DEVICE_OBJECT) + sizeof(EXTENDED_DEVOBJ_EXTENSION), 0, 0, RCAST<PVOID*>(&FileObjHook::FakeDeviceObject));
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("FileObjHook!GenerateHookObjects: Failed to create the fake device object with status 0x%X.", status);
		goto Exit;
	}

	DBGPRINT("FileObjHook!GenerateHookObjects: Created fake device at 0x%llx.", FileObjHook::FakeDeviceObject);

	//
	// Copy the existing object.
	//
	memcpy(FileObjHook::FakeDeviceObject, BaseDeviceObject, sizeof(DEVICE_OBJECT) + sizeof(EXTENDED_DEVOBJ_EXTENSION));

	FileObjHook::FakeDeviceObject->DriverObject = fakeDriverObject;
	fakeDriverObject->DeviceObject = FileObjHook::FakeDeviceObject;

	//
	// Hook the device control entry of the MajorFunction member.
	//
	switch (this->HookType)
	{
	case DirectHook:
		//
		// Place hooks and store old function.
		//
		for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
		{
			FileObjHook::OriginalDispatch[i] = fakeDriverObject->MajorFunction[i];
			fakeDriverObject->MajorFunction[i] = this->DispatchHook;
		}
		break;
	}

	//
	// For now, redirect everything to IRP DeviceIoControl by disabling FastIo.
	// TODO: Implement FastIo hooking.
	//
	FileObjHook::FakeDeviceObject->DriverObject->FastIoDispatch = NULL;
Exit:
	return TRUE;
}

/**
	Hook a target file object.
	@param FileObject - The file object to hook.
	@return Whether hooking was successful.
*/
BOOLEAN
FileObjHook::HookFileObject (
	_In_ PFILE_OBJECT FileObject
	)
{
	PDEVICE_OBJECT oldDeviceObject;

	//
	// Check if we've already hooked this FILE_OBJECT.
	//
	if (FileObject->DeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] == this->DispatchHook)
	{
		return TRUE;
	}
	//
	// Generate the hook objects such as the fake driver and device object.
	//
	else if (FileObjHook::FakeDeviceObject == NULL)
	{
		if (this->GenerateHookObjects(FileObject->DeviceObject) == FALSE)
		{
			DBGPRINT("FileObjHook!HookFileObject: Failed to generate hook objects, aborting.");
			return FALSE;
		}
	}
	
	//
	// Atomically hook the device object of the file.
	//
	oldDeviceObject = reinterpret_cast<PDEVICE_OBJECT>(InterlockedExchange64(RCAST<PLONG64>(&FileObject->DeviceObject), RCAST<LONG64>(FileObjHook::FakeDeviceObject)));

	//
	// If we hit this assert, it means we're hooking a different device which should never happen.
	//
	NT_ASSERT(FileObjHook::OriginalDeviceObject == NULL || FileObjHook::OriginalDeviceObject == oldDeviceObject);

	FileObjHook::OriginalDeviceObject = oldDeviceObject;
	return TRUE;
}

/**
	System thread function to automatically hook new file objects that match the TargetDeviceName.
	@param Arg1 - Unreferenced parameter.
*/
VOID
FileObjHook::RehookThread (
	_In_ PVOID Arg1
	)
{
	POBJECT_HEADER_NAME_INFO fileDeviceName;
	LARGE_INTEGER sleepInterval;
	ULONG hookCount;

	UNREFERENCED_PARAMETER(Arg1);

	//
	// Sleep for HOOK_UPDATE_TIME seconds after hooking.
	//
	sleepInterval.QuadPart = SECONDS_TO_SYSTEMTIME(HOOK_UPDATE_TIME);
	sleepInterval.QuadPart *= -1;

	//
	// Query the device name we're gonna be hooking.
	//
	fileDeviceName = SCAST<POBJECT_HEADER_NAME_INFO>(ObQueryNameInfo(FileObjHook::OriginalDeviceObject));

	while (TRUE)
	{
		//
		// Search for new objects and hook those as well.
		//
		CurrentObjHook->SearchAndHook(fileDeviceName->Name.Buffer, &hookCount);

		//
		// Sleep for designated time.
		//
		KeDelayExecutionThread(KernelMode, FALSE, &sleepInterval);
	}
}

/**
	The base hook for all hooks. Necessary to call the HookFunction with proper arguments such as the original DEVICE_OBJECT.
	@param DeviceObject - The alleged DeviceObject for the IRP_MJ_DEVICE_CONTROL call. May not be correct.
	@param Irp - The IRP for the IRP_MJ_DEVICE_CONTROL call.
	@return The status of the IRP_MJ_DEVICE_CONTROL call.
*/
NTSTATUS
FileObjHook::DispatchHook (
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
	)
{
	PIO_STACK_LOCATION irpStackLocation;

	UNREFERENCED_PARAMETER(DeviceObject);

	irpStackLocation = IoGetCurrentIrpStackLocation(Irp);

	//
	// When a hooked handle is being closed, we need to restore the original device object.
	//
	if (irpStackLocation->MajorFunction == IRP_MJ_CLOSE)
	{
		//
		// Set the current device object to the original device object.
		//
		irpStackLocation->FileObject->DeviceObject = FileObjHook::OriginalDeviceObject;

		DBGPRINT("FileObjHook!DispatchHook: Unhooked process 0x%X, file object 0x%llx, device object 0x%llx.", PsGetCurrentProcessId(), irpStackLocation->FileObject, DeviceObject);
	}

	//
	// Make sure we don't enter a recursive loop.
	//
	NT_ASSERT(FileObjHook::OriginalDispatch[irpStackLocation->MajorFunction] != FileObjHook::DispatchHook);

	return FileObjHook::HookFunction(FileObjHook::OriginalDispatch[irpStackLocation->MajorFunction], FileObjHook::OriginalDeviceObject, Irp);
}