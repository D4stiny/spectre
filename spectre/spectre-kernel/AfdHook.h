/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "FileObjHook.h"
#include "PacketDispatch.h"

//
// Handles IOCTL messages from the \Device\Afd hook.
//
typedef class AfdHook
{
	static VOID ProcessMaliciousPacket (
		_In_ PVOID RecvBuffer,
		_In_ ULONG RecvBufferSize,
		_In_ ULONG MagicOffset,
		_In_ PFILE_OBJECT SocketFileObject,
		_In_ PDEVICE_OBJECT OriginalDeviceObject,
		_In_ PAFD_RECV_INFO RecvInformation
		);
	static NTSTATUS HookAfdIoctl (
		_In_ DRIVER_DISPATCH OriginalFunction,
		_In_ PDEVICE_OBJECT DeviceObject,
		_Inout_ PIRP Irp
		);
	//
	// The FileObjHook instance used to intercept communication with the Afd.sys driver.
	//
	PFILE_OBJ_HOOK AfdDeviceHook;
public:
	AfdHook (
		_In_ PNTSTATUS Status
		);
} AFD_HOOK, *PAFD_HOOK;

#define AFD_DEVICE_NAME L"\\Device\\Afd"
#define AFD_HOOK_TAG DEFINE_TAG('hApS')
#define AFD_FILE_HOOK_TAG DEFINE_TAG('hFpS')
#define AFD_PACKET_DISPATCH_TAG DEFINE_TAG('dPpS')