/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#if _KERNEL_MODE == 1
#include <fltKernel.h>
#else
#include <Windows.h>
#endif

//
// The magic value to look for in packets. Indicates a malicious packet.
//
#define PACKET_MAGIC 0xDEADBEEF

typedef enum _PACKET_TYPE
{
	None,	// Used to check if a machine/port is infected.
	Command	// Used to issue a command and respond to a command request.
} PACKET_TYPE;

typedef struct _BASE_PACKET
{
	DWORD Magic;		// Indicates that the packet is malicious.
	DWORD PacketLength;	// The length of the packet.
	PACKET_TYPE Type;	// Indicates the type of packet.
} BASE_PACKET, *PBASE_PACKET;

typedef struct _COMMAND_PACKET
{
	BASE_PACKET Base;				// Contains standard information about the packet.
	DWORD CommandResponseLength;	// The length of the command/response.
	DWORD CommandResponseXorKey;	// The XOR key used to obfuscate the command/response.
	CHAR CommandResponse[1];		// The XOR'd command/response to execute.
} COMMAND_PACKET, *PCOMMAND_PACKET;