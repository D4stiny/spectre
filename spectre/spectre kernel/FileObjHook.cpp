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
PDRIVER_DISPATCH FileObjHook::OriginalDispatch;
PDRIVER_OBJECT FileObjHook::OriginalDriverObject;
LARGE_INTEGER FileObjHook::LastHookTime;

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
	this->HookType = Type;
	this->HookFunction = Hook;
	CurrentObjHook = this;
	this->SearchAndHook(TargetDeviceName);
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
	@return Whether hooking was successful.
*/
BOOLEAN
FileObjHook::SearchAndHook (
	_In_ PWCHAR TargetDeviceName
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
		if (currentFileObject->Size != sizeof(FILE_OBJECT))
		{
			DBGPRINT("FileObjHook!SearchAndHook: FILE_OBJECT 0x%llx has invalid size 0x%X.", currentFileObject, currentFileObject->Size);
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
		if (fileDeviceName && fileDeviceName->Name.Buffer && currentFileObject->DeviceObject->DriverObject && wcscmp(fileDeviceName->Name.Buffer, TargetDeviceName) == 0)
		{
			DBGPRINT("FileObjHook!SearchAndHook: Found a target device with name %wZ and device object 0x%llx, hooking.", fileDeviceName->Name, currentFileObject->DeviceObject);
			if (this->HookFileObject(currentFileObject) == FALSE)
			{
				DBGPRINT("FileObjHook!SearchAndHook: Failed to hook FILE_OBJECT 0x%llx.", currentFileObject);
				continue;
			}
			DBGPRINT("FileObjHook!SearchAndHook: Hooked FILE_OBJECT 0x%llx.", currentFileObject);
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
	@param BaseDriverObject - The driver object to copy.
	@return Whether the objects were generated successfully.
*/
BOOLEAN
FileObjHook::GenerateHookObjects (
	_In_ PDRIVER_OBJECT BaseDriverObject
	)
{
	NTSTATUS status;
	PVOID driverTextBase;
	SIZE_T driverTextSize;
	PVOID driverJmpGadget;

	this->OriginalDispatch = NULL;

	//
	// Allocate space for the fake DRIVER_OBJECT.
	//
	this->FakeDriverObject = SCAST<PDRIVER_OBJECT>(ExAllocatePoolWithTag(NonPagedPoolNx, BaseDriverObject->Size, DRIVER_OBJECT_TAG));
	if (this->FakeDriverObject == NULL)
	{
		DBGPRINT("FileObjHook!GenerateHookObjects: Could not allocate %i bytes for a fake driver object.", BaseDriverObject->Size);
		return FALSE;
	}

	//
	// Copy the existing object.
	//
	memcpy(this->FakeDriverObject, BaseDriverObject, BaseDriverObject->Size);

	//
	// Hook the device control entry of the MajorFunction member.
	//
	switch (this->HookType)
	{
	case DirectHook:
		//
		// For a direct hook, simply replace the IRP_MJ_DEVICE_CONTROL major function with the hook function.
		//
		this->OriginalDispatch = reinterpret_cast<PDRIVER_DISPATCH>(InterlockedExchange64(RCAST<PLONG64>(&this->FakeDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]), RCAST<LONG64>(this->DispatchHook)));
		break;
	case JmpRcxHook:
		//
		// Query the ".text" section of the driver to find a "jmp rcx" gadget.
		//
		status = Utilities::FindModuleTextSection(BaseDriverObject->DriverStart, &driverTextBase, &driverTextSize);
		if (NT_SUCCESS(status) == FALSE)
		{
			DBGPRINT("FileObjHook!GenerateHookObjects: Failed to find the \".text\" section of the %wZ driver.", BaseDriverObject->DriverName);
			break;
		}

		//
		// Search for the bytes 0xFF and 0xE1 which is simply an assembled version of "jmp rcx".
		//
		driverJmpGadget = Utilities::FindPattern(driverTextBase, driverTextSize, "\xFF\xE1", "xx");
		if (driverJmpGadget == NULL)
		{
			DBGPRINT("FileObjHook!GenerateHookObjects: Failed to find a \"jmp rcx\" gadget in the \".text\" section of the %wZ driver.", BaseDriverObject->DriverName);
			break;
		}

		//
		// First, set the IRP_MJ_DEVICE_CONTROL major function to point at the "jmp rcx" gadget.
		// This means that when DeviceIoControl is called, it will call "jmp rcx", which in turn
		// calls the first argument (aka rcx). The first argument of DRIVER_DISPATCH is the
		// DriverObject's DeviceObject, which we can control. We simply need to store the old
		// DeviceObject to pass to any hooks or the original function.
		//
		this->OriginalDispatch = reinterpret_cast<PDRIVER_DISPATCH>(InterlockedExchange64(RCAST<PLONG64>(&this->FakeDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]), RCAST<LONG64>(driverJmpGadget)));
		//
		// Set a DeviceObject value pointing at our hook function.
		//
		this->FakeDriverObject->DeviceObject = RCAST<PDEVICE_OBJECT>(this->DispatchHook);
		break;
	}

	return this->FakeDriverObject != NULL && this->OriginalDispatch != NULL;
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
	//
	// Check if we need to generate the hook objects such as the fake driver object.
	//
	if (this->FakeDriverObject == NULL || this->OriginalDispatch == NULL)
	{
		if (this->GenerateHookObjects(FileObject->DeviceObject->DriverObject) == FALSE)
		{
			DBGPRINT("FileObjHook!HookFileObject: Failed to generate hook objects, aborting.");
			return FALSE;
		}
	}

	//
	// Check if we've already hooked this FILE_OBJECT.
	//
	else if (FileObject->DeviceObject->DriverObject == this->FakeDriverObject)
	{
		return TRUE;
	}

	//
	// Atomically hook the device object of the file.
	//
	this->OriginalDriverObject = reinterpret_cast<PDRIVER_OBJECT>(InterlockedExchange64(RCAST<PLONG64>(&FileObject->DeviceObject->DriverObject), RCAST<LONG64>(this->FakeDriverObject)));
	return TRUE;
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
	LARGE_INTEGER currentTime;
	PDEVICE_OBJECT actualDeviceObject;
	POBJECT_HEADER_NAME_INFO fileDeviceName;

	actualDeviceObject = NULL;

	switch (FileObjHook::HookType)
	{
	case DirectHook:
		//
		// For a direct hook, we can just pass the same arguments we got to the HookFunction.
		//
		actualDeviceObject = DeviceObject;
		break;
	case JmpRcxHook:
		//
		// For a "jmp rcx" hook, we need to pass the real DeviceObject value.
		//
		actualDeviceObject = FileObjHook::OriginalDriverObject->DeviceObject;
		break;
	}

	//
	// Check if it's been the HOOK_UPDATE_TIME time interval since the last hook update.
	//
	KeQuerySystemTime(&currentTime);
	if (SYSTEM_TIME_TO_SECONDS(currentTime) - SYSTEM_TIME_TO_SECONDS(FileObjHook::LastHookTime) > HOOK_UPDATE_TIME)
	{
		DBGPRINT("FileObjHook!DispatchHook: Detected time interval %i elapsed, rehooking.", HOOK_UPDATE_TIME);
		//
		// Query the name of the associated DEVICE_OBJECT.
		//
		fileDeviceName = SCAST<POBJECT_HEADER_NAME_INFO>(ObQueryNameInfo(actualDeviceObject));

		//
		// Search for new objects and hook those as well.
		//
		CurrentObjHook->SearchAndHook(fileDeviceName->Name.Buffer);

		//
		// Update the last hook time.
		//
		FileObjHook::LastHookTime = currentTime;
	}

	return FileObjHook::HookFunction(FileObjHook::OriginalDispatch, actualDeviceObject, Irp);
}