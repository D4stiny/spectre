/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "Utils.h"

typedef enum HookType
{
	DirectHook,	// A direct hook indicates that the FileObjHook should simply set the IRP_MJ_DEVICE_CONTROL entry of the DriverObject to the hook function.
	JmpRcxHook	// A JMP RCX hook indicates that the FileObjHook should attempt to find a "jmp rcx" instruction, set the IRP_MJ_DEVICE_CONTROL entry to that gadget, and set the device object to the hook function.
} HOOK_TYPE;

typedef NTSTATUS
HOOK_DISPATCH (
	_In_ DRIVER_DISPATCH OriginalFunction,
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
	);

//
// Time interval before updating hooks for the FILE_OBJECT.
//
#define HOOK_UPDATE_TIME 10

typedef HOOK_DISPATCH* PHOOK_DISPATCH;

typedef class FileObjHook
{
	BOOLEAN HookFileObject (
		_In_ PFILE_OBJECT FileObject
		);

	BOOLEAN IsHandleFile (
		_In_ PEPROCESS Process,
		_In_ HANDLE Handle
		);

	BOOLEAN SearchAndHook (
		_In_ PWCHAR TargetDeviceName
		);

	BOOLEAN GenerateHookObjects (
		_In_ PDRIVER_OBJECT BaseDriverObject
		);

	static NTSTATUS DispatchHook (
		_In_ PDEVICE_OBJECT DeviceObject,
		_Inout_ PIRP Irp
		);

	//
	// The method of hooking to be performed.
	//
	static HOOK_TYPE HookType;
	//
	// The function to redirect IOCTLs to.
	//
	static PHOOK_DISPATCH HookFunction;
	//
	// The hooked version of the target device object.
	//
	PDRIVER_OBJECT FakeDriverObject;
	//
	// The original driver object before hooking.
	//
	static PDRIVER_OBJECT OriginalDriverObject;
	//
	// The original driver dispatch function.
	//
	static PDRIVER_DISPATCH OriginalDispatch;
	//
	// The last time hooks were updated.
	//
	static LARGE_INTEGER LastHookTime;
public:
	//
	// Whether or not there is an ongoing hook.
	//
	BOOLEAN ObjectsHooked;

	FileObjHook (
		_In_ PWCHAR TargetDeviceName,
		_In_ HOOK_TYPE Type,
		_In_ HOOK_DISPATCH Hook
		);
	~FileObjHook (
		VOID
		);
} FILE_OBJ_HOOK, *PFILE_OBJ_HOOK;

#define HANDLE_INFO_TAG 'iHpS'
#define OBJECT_TYPE_TAG 'tOpS'
#define DEVICE_OBJECT_TAG 'iveD'
#define DRIVER_OBJECT_TAG 'virD'

#define SYSTEM_TIME_TO_SECONDS(systemtime) systemtime.QuadPart / 10000000

extern PFILE_OBJ_HOOK CurrentObjHook;