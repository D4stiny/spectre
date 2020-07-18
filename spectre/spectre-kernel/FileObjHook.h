/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "Utils.h"

typedef enum class HookType
{
	DirectHook	// A direct hook indicates that the FileObjHook should simply set the IRP_MJ_DEVICE_CONTROL entry of the DriverObject to the hook function.
} HOOK_TYPE;

typedef NTSTATUS
HOOK_DISPATCH (
	_In_ DRIVER_DISPATCH OriginalFunction,
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
	);

typedef struct NamedDeviceObject
{
	CHAR ObjectNameHeaderPadding[sizeof(OBJECT_HEADER_NAME_INFO)];
	CHAR ObjectHeaderPadding[FIELD_OFFSET(OBJECT_HEADER, Body)];
	DEVICE_OBJECT DeviceObject;
} NAMED_DEVICE_OBJECT, *PNAMED_DEVICE_OBJECT;

#define OBJECT_NAME_OFFSET (sizeof(OBJECT_HEADER_NAME_INFO) + FIELD_OFFSET(OBJECT_HEADER, Body))

//
// Time interval (milliseconds) before updating hooks for the FILE_OBJECT.
//
#define HOOK_UPDATE_TIME 2000

typedef HOOK_DISPATCH* PHOOK_DISPATCH;

typedef class FileObjHook
{
	BOOLEAN HookFileObject (
		_In_ PFILE_OBJECT FileObject
		);

	BOOLEAN IsFileObject (
		_In_ PVOID Object,
		_In_ BYTE ObjectTypeNumber
		);

	BOOLEAN SearchAndHook (
		_Inout_ ULONG* HookCount
		);

	BOOLEAN GenerateHookObjects (
		_In_ PDEVICE_OBJECT BaseDeviceObject
		);

	static NTSTATUS DispatchHook (
		_In_ PDEVICE_OBJECT DeviceObject,
		_Inout_ PIRP Irp
		);

	static VOID RehookThread(
		_In_ PVOID Arg1
		);

	//
	// The method of hooking to be performed.
	//
	static HOOK_TYPE HookType;
	//
	// The function to redirect IOCTLs to.
	//
	static PHOOK_DISPATCH HookMajorFunction;
	//
	// The fake hooked device object.
	//
	static PDEVICE_OBJECT FakeDeviceObject;
	//
	// The original device object before hooking.
	//
	static PDEVICE_OBJECT OriginalDeviceObject;
	//
	// The original driver dispatch functions.
	//
	static PDRIVER_DISPATCH OriginalDispatch[IRP_MJ_MAXIMUM_FUNCTION + 1];
	//
	// The functions to redirect FastIo operations to.
	//
	static PFAST_IO_DISPATCH HookFastIoTable;
public:
	//
	// Whether or not there is an ongoing hook.
	//
	BOOLEAN ObjectsHooked;
	//
	// The original FastIo functions.
	//
	static FAST_IO_DISPATCH OriginalFastIo;

	FileObjHook (
		_In_ PDEVICE_OBJECT TargetDeviceObject,
		_In_ HOOK_TYPE Type,
		_In_ HOOK_DISPATCH MajorFunctionHook,
		_In_ PFAST_IO_DISPATCH FastIoHook
		);
	~FileObjHook (
		VOID
		);
} FILE_OBJ_HOOK, *PFILE_OBJ_HOOK;

#define HANDLE_INFO_TAG DEFINE_TAG('iHpS')
#define OBJECT_TYPE_TAG DEFINE_TAG('tOpS')
#define FAST_IO_TABLE_TAG DEFINE_TAG('iFpS')
#define DEVICE_OBJECT_TAG DEFINE_TAG('iveD')
#define DRIVER_OBJECT_TAG DEFINE_TAG('virD')
#define FILE_OBJECT_LOCK_TAG DEFINE_TAG('lFpS')

extern PFILE_OBJ_HOOK CurrentObjHook;