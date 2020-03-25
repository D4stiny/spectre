/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "FileObjHook.h"
#include "PacketHandler.h"

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
	static BOOLEAN PopulateMaliciousPacket (
		_Inout_ PBASE_PACKET FullBasePacket,
		_In_ PBASE_PACKET PartialBasePacket,
		_In_ PFILE_OBJECT SocketFileObject,
		_In_ PDEVICE_OBJECT OriginalDeviceObject,
		_In_ PAFD_RECV_INFO RecvInformation,
		_In_ PVOID RecvBuffer,
		_In_ ULONG RecvBufferSize,
		_In_ ULONG MagicOffset
		);
	static BOOLEAN PopulateBasePacket (
		_Inout_ PBASE_PACKET BasePacket,
		_In_ PFILE_OBJECT SocketFileObject,
		_In_ PDEVICE_OBJECT OriginalDeviceObject,
		_In_ PAFD_RECV_INFO RecvInformation,
		_In_ PVOID RecvBuffer,
		_In_ ULONG RecvBufferSize,
		_In_ ULONG MagicOffset,
		_Inout_ ULONG* RemainingBytes
		);
	static NTSTATUS HookAfdIoctl (
		_In_ DRIVER_DISPATCH OriginalFunction,
		_In_ PDEVICE_OBJECT DeviceObject,
		_Inout_ PIRP Irp
		);
	static BOOLEAN SendBuffer (
		_In_ PFILE_OBJECT SocketFileObject,
		_In_ PDEVICE_OBJECT OriginalDeviceObject,
		_In_ CHAR* Buffer,
		_In_ SIZE_T BufferSize,
		_In_ ULONG AfdFlags,
		_In_ ULONG TdiFlags
		);
	static BOOLEAN ReceiveBuffer (
		_In_ PFILE_OBJECT SocketFileObject,
		_In_ PDEVICE_OBJECT OriginalDeviceObject,
		_In_ CHAR* Buffer,
		_In_ SIZE_T BufferSize,
		_In_ ULONG AfdFlags,
		_In_ ULONG TdiFlags,
		_Inout_ ULONG* BytesReceived
		);
	//
	// The FileObjHook instance used to intercept communication with the Afd.sys driver.
	//
	PFILE_OBJ_HOOK AfdDeviceHook;
public:
	AfdHook (
		VOID
		);
} AFD_HOOK, *PAFD_HOOK;

#define AFD_DEVICE_BASE_NAME L"Afd"
#define AFD_FILE_HOOK_TAG 'hFpS'
#define MALICIOUS_PACKET_TAG 'pMpS'