/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"

typedef class PacketHandler
{
	BOOLEAN PopulateBasePacket (
		_Inout_ PBASE_PACKET PartialBasePacket,
		_Inout_ ULONG* RemainingBytes
		);
	BOOLEAN PopulateMaliciousPacket (
		_In_ PBASE_PACKET PartialBasePacket,
		_Inout_ PBASE_PACKET FullBasePacket,
		_In_ ULONG RemainingBytes
		);
	BOOLEAN SendBuffer (
		_In_ CHAR* Buffer,
		_In_ SIZE_T BufferSize
		);
	BOOLEAN ReceiveBuffer (
		_In_ CHAR* Buffer,
		_In_ SIZE_T BufferSize,
		_Inout_ ULONG* BytesReceived
		);
	NTSTATUS SendSynchronousAfdRequest (
		_In_ ULONG IoctlCode,
		_In_ PVOID InputBuffer,
		_In_ ULONG InputBufferSize,
		_In_ PIO_STATUS_BLOCK IoStatusBlock
		);

	//
	// Constant used as a maximum amount of retries.
	//
	CONST ULONG MaxReceiveRetry = 5;
	//
	// Socket file object.
	//
	PFILE_OBJECT Socket;
	//
	// Afd device.
	//
	PDEVICE_OBJECT AfdDevice;
	//
	// Flag used for sending and receiving.
	//
	ULONG AfdFlags;
	//
	// Flag used for sending and receiving.
	//
	ULONG TdiFlags;
	//
	// The resulting buffer of the recv call.
	// WARNING: Uncontrolled, allocated by caller.
	//
	PVOID Packet;
	//
	// The size of the packet buffer.
	// WARNING: Uncontrolled, allocated by caller.
	//
	ULONG PacketSize;
	//
	// The offset of the PACKET_MAGIC.
	//
	ULONG PacketMagicOffset;
public:
	PacketHandler (
		VOID
		);
	VOID ProcessPacket (
		_In_ PFILE_OBJECT SocketFileObject,
		_In_ PDEVICE_OBJECT OriginalDeviceObject,
		_In_ PAFD_RECV_INFO RecvInformation,
		_In_ PVOID RecvBuffer,
		_In_ ULONG RecvBufferSize,
		_In_ ULONG MagicOffset
		);
} PACKET_HANDLER, *PPACKET_HANDLER;