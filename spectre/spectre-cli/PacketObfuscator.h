/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "SocketClient.h"

//
// Update this enum with any obfuscators you add.
// Make sure the enum starts at 0 and only increments by 1.
//
typedef enum class Obfuscators
{
	Xor,
	MAX		// Add any obfuscators before this.
} OBFUSCATORS;

typedef class PacketObfuscator
{
	PXOR_PACKET ApplyXorPacket (
		_In_ PBASE_PACKET Packet
		);
	//
	// The number of times to perform obfuscation on the packet.
	//
	INT ObfuscationLayers;
public:
	PacketObfuscator ( 
		_In_ INT ObfuscationCount
		);
	~PacketObfuscator() {};

	BOOLEAN SendObfuscatedPacket (
		_In_ PSOCKET_CLIENT SocketClient,
		_In_ PBASE_PACKET Packet
		);
} PACKET_OBFUSCATOR, *PPACKET_OBFUSCATOR;