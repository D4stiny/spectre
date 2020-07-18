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
PHOOK_DISPATCH FileObjHook::HookMajorFunction;
PDRIVER_DISPATCH FileObjHook::OriginalDispatch[IRP_MJ_MAXIMUM_FUNCTION + 1];
PDEVICE_OBJECT FileObjHook::OriginalDeviceObject;
PDEVICE_OBJECT FileObjHook::FakeDeviceObject;
PFAST_IO_DISPATCH FileObjHook::HookFastIoTable;
FAST_IO_DISPATCH FileObjHook::OriginalFastIo;

//
// Represents the current hook object needed by the dispatch function.
//
PFILE_OBJ_HOOK CurrentObjHook;

/**
	Initialize the FileObjHook class.
	@param TargetDeviceObject - Pointer to the device to target.
	@param Type - Method of hooking.
	@param MajorFunctionHook - The function to redirect each MajorFunction to.
	@param FastIoHook - Optional hooks for the FastIo dispatch table.
*/
FileObjHook::FileObjHook (
	_In_ PDEVICE_OBJECT TargetDeviceObject,
	_In_ HOOK_TYPE Type,
	_In_ HOOK_DISPATCH MajorFunctionHook,
	_In_opt_ PFAST_IO_DISPATCH FastIoHook
	)
{
	RTL_PROCESS_MODULE_INFORMATION ntoskrnlModule;
	
	this->HookType = Type;
	this->HookMajorFunction = MajorFunctionHook;
	CurrentObjHook = this;
	this->ObjectsHooked = FALSE;

	//
	// If we're hooking FastIo, allocate a new object for it.
	//
	if (FastIoHook)
	{
		FileObjHook::HookFastIoTable = RCAST<PFAST_IO_DISPATCH>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(FAST_IO_DISPATCH), FAST_IO_TABLE_TAG));
		if (FileObjHook::HookFastIoTable == NULL)
		{
			DBGPRINT("FileObjHook!FileObjHook: Failed to allocate memory for FastIo hook table.");
			return;
		}

		//
		// Copy the hook table over.
		//
		memcpy(FileObjHook::HookFastIoTable, FastIoHook, sizeof(FAST_IO_DISPATCH));
	}
	
	//
	// Set the original device object.
	//
	this->OriginalDeviceObject = TargetDeviceObject;

	//
	// Retrieve the ntoskrnl module.
	//
	ntoskrnlModule = Utilities::GetDriverModule("ntoskrnl.exe");

	//
	// If we don't get a valid ntoskrnl module, we have much more serious problems...
	//
	NT_ASSERT(ntoskrnlModule.ImageBase);

	//
	// Start the scanning thread.
	//
	if (Utilities::CreateHiddenThread(ntoskrnlModule.ImageBase, FileObjHook::RehookThread) == FALSE)
	{
		DBGPRINT("FileObjHook!FileObjHook: Failed to start scanning function.");
		return;
	}
}

/**
	Check if a Object is a FILE_OBJECT.
	@param Object - The object to check.
	@param ObjectTypeNumber - The type index for the object.
	@return TRUE if Object is a FILE_OBJECT, otherwise FALSE.
*/
BOOLEAN
FileObjHook::IsFileObject (
	_In_ PVOID Object,
	_In_ BYTE ObjectTypeNumber
	)
{
	POBJECT_TYPE objectType;
	static BYTE fileObjectTypeNumber = 0;

	if (fileObjectTypeNumber == 0)
	{
		//
		// We generally want to use the object type number,
		// but until we know it, we need to query the object type.
		//
		objectType = ObGetObjectType(Object);
		if (objectType == NULL)
		{
			DBGPRINT("FileObjHook!IsFileObject: Failed to query object type.");
			return FALSE;
		}

		//
		// If the object is a FILE_OBJECT...
		//
		if (objectType == *IoFileObjectType)
		{
			//
			// Set the static file object type number
			// now that we have a confirmed file object.
			//
			fileObjectTypeNumber = ObjectTypeNumber;
			return TRUE;
		}
		return FALSE;
	}

	//
	// File objects should have the same
	// type number.
	//
	return fileObjectTypeNumber == ObjectTypeNumber;
}

/**
	Search for handles to a file object and hook objects that match TargetDeviceName.
	@param HookCount - Caller-allocated variable to store the number of hooks placed by the function.
	@return Whether hooking was successful.
*/
BOOLEAN
FileObjHook::SearchAndHook (
	_Inout_ ULONG* HookCount
	)
{
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION systemHandleInformation;
	ULONG systemHandleInformationSize;
	ULONG i;
	SYSTEM_HANDLE currentSystemHandle;
	PFILE_OBJECT currentFileObject;

	UNREFERENCED_PARAMETER(HookType);

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
		if (currentSystemHandle.Object == NULL)
		{
			continue;
		}

		//
		// Skip non-FILE_OBJECT handles.
		//
		if (IsFileObject(currentSystemHandle.Object, currentSystemHandle.ObjectTypeNumber) == FALSE)
		{
			continue;
		}

		currentFileObject = SCAST<PFILE_OBJECT>(currentSystemHandle.Object);

		//
		// TODO: Add a try/catch wrapper around the following to prevent race condition issues.
		// For now, do not change anything to observe issues that occur without a try/catch.
		//
		if (currentFileObject->Size != sizeof(FILE_OBJECT))
		{
			DBGPRINT("FileObjHook!SearchAndHook: FILE_OBJECT 0x%llx has invalid size 0x%X.", currentFileObject, currentFileObject->Size);
			continue;
		}

		//
		// Check if this is the device we're after.
		//
		if (currentFileObject->DeviceObject == FileObjHook::OriginalDeviceObject)
		{
			//DBGPRINT("FileObjHook!SearchAndHook: Found a target device with name %wZ and device object 0x%llx, hooking.", fileDeviceName->Name, currentFileObject->DeviceObject);
			if (this->HookFileObject(currentFileObject) == FALSE)
			{
				DBGPRINT("FileObjHook!SearchAndHook: Failed to hook FILE_OBJECT 0x%llx.", currentFileObject);
				continue;
			}
			//DBGPRINT("FileObjHook!SearchAndHook: Hooked FILE_OBJECT 0x%llx.", currentFileObject);
			(*HookCount)++;
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
	CSHORT fakeDeviceObjectSize;

	OBJECT_ATTRIBUTES fakeDeviceAttributes;
	POBJECT_HEADER_NAME_INFO realDeviceNameHeader;

	PVOID* originalFastIoFunctions;
	PVOID* hookedFastIoFunctions;

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
	status = ObCreateObject(KernelMode,
							*IoDriverObjectType,
							&fakeDriverAttributes,
							KernelMode,
							NULL,
							fakeDriverObjectSize,
							0,
							0,
							RCAST<PVOID*>(&fakeDriverObject));
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

	//
	// Sanity checks
	//
	NT_ASSERT(realDeviceNameHeader);
	if (realDeviceNameHeader == NULL)
	{
		DBGPRINT("FileObjHook!GenerateHookObjects: Failed to query object name info.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}

	//
	// Generate the object attributes for the fake device object.
	//
	InitializeObjectAttributes(&fakeDeviceAttributes,
							   &realDeviceNameHeader->Name,
							   OBJ_KERNEL_HANDLE | OBJ_PERMANENT,
							   NULL,
							   BaseDeviceObject->SecurityDescriptor);

	fakeDeviceObjectSize = sizeof(DEVICE_OBJECT) + sizeof(EXTENDED_DEVOBJ_EXTENSION);

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
	status = ObCreateObject(KernelMode,
							*IoDeviceObjectType,
							&fakeDeviceAttributes,
							KernelMode,
							NULL,
							fakeDeviceObjectSize,
							0,
							0,
							RCAST<PVOID*>(&FileObjHook::FakeDeviceObject));
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("FileObjHook!GenerateHookObjects: Failed to create the fake device object with status 0x%X.", status);
		goto Exit;
	}

	//
	// Copy the existing object.
	//
	memcpy(FileObjHook::FakeDeviceObject, BaseDeviceObject, fakeDeviceObjectSize);

	DBGPRINT("FileObjHook!GenerateHookObjects: Created fake device at 0x%llx.", FileObjHook::FakeDeviceObject);

	//
	// Update the driver and device object attributes in the respective objects.
	//
	FileObjHook::FakeDeviceObject->DriverObject = fakeDriverObject;
	fakeDriverObject->DeviceObject = FileObjHook::FakeDeviceObject;

	//
	// Hook the device control entry of the MajorFunction member.
	//
	switch (this->HookType)
	{
	case HookType::DirectHook:
		//
		// Place MajorFunction hooks and store the original function.
		//
		for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
		{
			FileObjHook::OriginalDispatch[i] = fakeDriverObject->MajorFunction[i];
			fakeDriverObject->MajorFunction[i] = this->DispatchHook;
		}

		//
		// Place FastIo hooks and store the original function.
		//
		if (fakeDriverObject->FastIoDispatch)
		{
			if (FileObjHook::HookFastIoTable)
			{
				//
				// After the ULONG size, it's just an array of pointers.
				//
				originalFastIoFunctions = RCAST<PVOID*>(RCAST<ULONG64>(fakeDriverObject->FastIoDispatch) + FIELD_OFFSET(FAST_IO_DISPATCH, SizeOfFastIoDispatch));
				hookedFastIoFunctions = RCAST<PVOID*>(RCAST<ULONG64>(FileObjHook::HookFastIoTable) + FIELD_OFFSET(FAST_IO_DISPATCH, SizeOfFastIoDispatch));
				for (i = 0; i < FAST_IO_DISPATCH_COUNT; i++)
				{
					//
					// Make sure to copy any entry in the original dispatch table that isn't hooked.
					//
					if (originalFastIoFunctions[i] && hookedFastIoFunctions[i] == NULL)
					{
						hookedFastIoFunctions[i] = originalFastIoFunctions[i];
						DBGPRINT("FileObjHook!GenerateHookObjects: Imported unhooked FastIo dispatch entry at index %i.", i);
					}
				}

				//
				// Store the original table.
				//
				memcpy(&FileObjHook::OriginalFastIo, fakeDriverObject->FastIoDispatch, sizeof(FAST_IO_DISPATCH));

				//
				// Set the new dispatch table to point to our hook table.
				//
				fakeDriverObject->FastIoDispatch = FileObjHook::HookFastIoTable;
			}
			//
			// If FastIo is enabled for the driver and we don't have any FastIo hooks, disable FastIo.
			//
			else
			{
				fakeDriverObject->FastIoDispatch = NULL;
				DBGPRINT("FileObjHook!GenerateHookObjects: WARNING: Driver has FastIo, but no hooks specified! Disabling.", i);
			}
		}
		break;
	}
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
	PRKMUTEX fileObjectLock;

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
	// Allocate space for a lock.
	//
	fileObjectLock = RCAST<PRKMUTEX>(ExAllocatePoolWithTag(NonPagedPool, sizeof(KMUTEX), FILE_OBJECT_LOCK_TAG));
	if (fileObjectLock == NULL)
	{
		DBGPRINT("FileObjHook!HookFileObject: Failed to allocate lock object, aborting.");
		return FALSE;
	}

	memset(fileObjectLock, 0, sizeof(KMUTEX));
	KeInitializeMutex(fileObjectLock, 0);
	
	//
	// Sanity check.
	//
	if (FileObject->FsContext2)
	{
		NT_ASSERT(FALSE);
	}

	//
	// Set the context of the file object to our lock.
	//
	FileObject->FsContext2 = fileObjectLock;

	//
	// Atomically hook the device object of the file.
	//
	oldDeviceObject = RCAST<PDEVICE_OBJECT>(InterlockedExchange64(RCAST<PLONG64>(&FileObject->DeviceObject), RCAST<LONG64>(FileObjHook::FakeDeviceObject)));

	//
	// If we hit this assert, it means we're hooking a different device which should never happen.
	//
	NT_ASSERT(FileObjHook::OriginalDeviceObject == oldDeviceObject);

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
	LARGE_INTEGER sleepInterval;
	ULONG hookCount;

	UNREFERENCED_PARAMETER(Arg1);

	hookCount = 0;

	//
	// Sleep for HOOK_UPDATE_TIME seconds after hooking.
	//
	sleepInterval.QuadPart = MILLISECONDS_TO_SYSTEMTIME(HOOK_UPDATE_TIME);
	sleepInterval.QuadPart *= -1;

	while (TRUE)
	{
		//
		// Search for new objects and hook those as well.
		//
		CurrentObjHook->SearchAndHook(&hookCount);

		//
		// Sleep for designated time.
		// Let's not kill the CPU?
		//
		KeDelayExecutionThread(KernelMode, FALSE, &sleepInterval);
	}
}

/**
	The base hook for all hooks. Necessary to call the HookMajorFunction with proper arguments such as the original DEVICE_OBJECT.
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
	PRKMUTEX fileObjectLock;

	UNREFERENCED_PARAMETER(DeviceObject);

	irpStackLocation = IoGetCurrentIrpStackLocation(Irp);

	//
	// When a hooked handle is being closed, we need to restore the original device object.
	//
	if (irpStackLocation->MajorFunction == IRP_MJ_CLEANUP)
	{
		//
		// Set the current device object to the original device object.
		//
		irpStackLocation->FileObject->DeviceObject = FileObjHook::OriginalDeviceObject;

		//
		// Free our file object lock.
		// TODO: Investigate potential race conditions.
		//
		fileObjectLock = RCAST<PRKMUTEX>(irpStackLocation->FileObject->FsContext2);
		irpStackLocation->FileObject->FsContext2 = NULL;
		ExFreePoolWithTag(fileObjectLock, FILE_OBJECT_LOCK_TAG);

		DBGPRINT("FileObjHook!DispatchHook: Unhooked process 0x%X, file object 0x%llx, device object 0x%llx.", PsGetCurrentProcessId(), irpStackLocation->FileObject, DeviceObject);
	}

	//
	// Make sure we don't enter a recursive loop.
	//
	NT_ASSERT(FileObjHook::OriginalDispatch[irpStackLocation->MajorFunction] != FileObjHook::DispatchHook);

	return FileObjHook::HookMajorFunction(FileObjHook::OriginalDispatch[irpStackLocation->MajorFunction], FileObjHook::OriginalDeviceObject, Irp);
}