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
	Ping,	// Used to check if a machine/port is infected.
	Xor,	// Used to obfuscate the contents of a packet with XOR obfuscation.
} PACKET_TYPE;

typedef struct _BASE_PACKET
{
	ULONG PacketLength;	// The length of the packet.
	PACKET_TYPE Type;	// Indicates the type of packet.
} BASE_PACKET, *PBASE_PACKET;

typedef struct _MAGIC_BASE_PACKET
{
	ULONG Magic;		// Indicates that the packet is malicious.
	BASE_PACKET Base;	// Contains standard information about the packet.
} MAGIC_BASE_PACKET, *PMAGIC_BASE_PACKET;

#define MAGIC_SIZE (sizeof(MAGIC_BASE_PACKET) - sizeof(BASE_PACKET))

#pragma pack(push, 1)
typedef struct _XOR_PACKET
{
	BASE_PACKET Base;	// Contains standard information about the packet.
	BYTE XorKey;		// The XOR key used to obfuscate the packet.
	BYTE XorContent[1];	// The XOR'd packet to dispatch.
} XOR_PACKET, *PXOR_PACKET;
#pragma pack(pop)

#define XOR_PACKET_SIZE(contentLength) ((sizeof(XOR_PACKET) - 1) + contentLength)

//typedef struct _COMMAND_PACKET
//{
//	BASE_PACKET Base;				// Contains standard information about the packet.
//	ULONG CommandResponseLength;	// The length of the command/response.
//	ULONG CommandResponseXorKey;	// The XOR key used to obfuscate the command/response.
//	CHAR CommandResponse[1];		// The XOR'd command/response to execute.
//} COMMAND_PACKET, *PCOMMAND_PACKET;