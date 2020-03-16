/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"

typedef enum HookType
{
	DirectHook,	// A direct hook indicates that the FileObjHook should simply set the IRP_MJ_DEVICE_CONTROL entry of the DriverObject to the hook function.
	JmpRcxHook	// A JMP RCX hook indicates that the FileObjHook should attempt to find a "jmp rcx" instruction, set the IRP_MJ_DEVICE_CONTROL entry to that gadget, and set the device object to the hook function.
} HOOK_TYPE;

typedef
NTSTATUS
HOOK_DISPATCH (
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
	);

typedef class FileObjHook
{
	BOOLEAN HookFileObject (
		_In_ PFILE_OBJECT FileObject,
		_In_ HOOK_TYPE HookType,
		_In_ HOOK_DISPATCH HookFunction
		);

	BOOLEAN IsHandleFile (
		_In_ PEPROCESS Process,
		_In_ HANDLE Handle
		);

	BOOLEAN SearchAndHook (
		_In_ PWCHAR TargetDeviceName,
		_In_ HOOK_TYPE HookType,
		_In_ HOOK_DISPATCH HookFunction
		);

	static NTSTATUS DispatchHook (
		_In_ PDEVICE_OBJECT DeviceObject,
		_Inout_ PIRP Irp
		);

public:
	//
	// Whether or not there is an ongoing hook.
	//
	BOOLEAN ObjectsHooked;
	//
	// The original driver dispatch function.
	//
	DRIVER_DISPATCH OriginalDispatch;

	FileObjHook (
		_In_ PWCHAR TargetDeviceName,
		_In_ HOOK_TYPE HookType,
		_In_ HOOK_DISPATCH HookFunction
		);


} FILE_OBJ_HOOK, *PFILE_OBJ_HOOK;

#define HANDLE_INFO_TAG 'iHpS'
#define OBJECT_TYPE_TAG 'tOpS'
#define DEVICE_OBJECT_TAG 'iveD'
#define DRIVER_OBJECT_TAG 'virD'