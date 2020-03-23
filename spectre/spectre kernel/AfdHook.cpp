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

	irpStackLocation = IoGetCurrentIrpStackLocation(Irp);
	deviceControlRequest = FALSE;
	inputBuffer = NULL;
	ioControlCode = 0;

	//
	// Before calling the original function we need to save the passed parameters.
	//
	if (irpStackLocation->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		inputBuffer = irpStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
		inputBufferLength = irpStackLocation->Parameters.DeviceIoControl.InputBufferLength;
		ioControlCode = irpStackLocation->Parameters.DeviceIoControl.IoControlCode;
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
				// Make sure the first buffer can fit the magic value.
				//
				if (recvInformation->BufferArray[0].len < sizeof(DWORD))
				{
					goto Exit;
				}

				//
				// Check for the magic value.
				//
				if (*RCAST<DWORD*>(recvInformation->BufferArray[0].buf) != PACKET_MAGIC)
				{
					goto Exit;
				}

				DBGPRINT("AfdHook!HookAfdIoctl: Found magic in first buffer.");
			}
			__except (1)
			{

			}
		}
	}

Exit:
	return returnStatus;
}