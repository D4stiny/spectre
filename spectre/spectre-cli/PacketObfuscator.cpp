/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "PacketObfuscator.h"

/**
	Constructor for the PacketObfuscator class.
	@param ObfuscationCount - The number of times to perform obfuscation on the packet.
*/
PacketObfuscator::PacketObfuscator (
	_In_ INT ObfuscationCount
	)
{
	this->ObfuscationLayers = ObfuscationCount;
	//
	// This isn't cryptographically secure, but we don't need anything fancy.
	//
	srand(time(NULL));
}

/**
	Generate a XOR_PACKET as a layer of obfuscation.
	@param Packet - Pointer to the packet to obfuscate.
	@return Pointer to a XOR_PACKET structure, *must be free'd by caller*.
*/
PXOR_PACKET
PacketObfuscator::ApplyXorPacket (
	_In_ PBASE_PACKET Packet
	)
{
	PXOR_PACKET xorPacket;
	ULONG xorPacketSize;
	ULONG i;

	xorPacketSize = XOR_PACKET_SIZE(Packet->PacketLength);

	//
	// Allocate space for the XOR_PACKET structure.
	//
	xorPacket = RCAST<PXOR_PACKET>(malloc(xorPacketSize));
	if (xorPacket == NULL)
	{
		DBGPRINT("PacketObfuscator!ApplyXorPacket: Failed to allocate space for the XOR_PACKET structure.");
		return NULL;
	}

	memset(xorPacket, 0, xorPacketSize);
	xorPacket->Base.Type = PACKET_TYPE::Xor;
	xorPacket->Base.PacketLength = xorPacketSize;
	xorPacket->XorKey = rand() % 0xFF;

	//
	// Copy the original packet into the XorContent array.
	//
	memcpy(&xorPacket->XorContent, Packet, Packet->PacketLength);

	//
	// Perform XOR obfuscation.
	//
	for (i = 0; i < Packet->PacketLength; i++)
	{
		xorPacket->XorContent[i] ^= xorPacket->XorKey;
	}

	return xorPacket;
}

/**
	Send a packet with layers obfuscation.
	@param SocketClient - The socket client used to send the packet.
	@param Packet - The pointer to the packet to send.
	@return Whether or not sending the packet was successful.
*/
BOOLEAN
PacketObfuscator::SendObfuscatedPacket (
	_In_ PSOCKET_CLIENT SocketClient,
	_In_ PBASE_PACKET Packet
	)
{
	INT obfuscatorChoice;
	ULONG i;
	std::vector<PVOID> pointersToFree;
	PBASE_PACKET finalPacket;
	BOOLEAN success;
	CONST DWORD magicConstant = PACKET_MAGIC;

	finalPacket = Packet;

	for (i = 0; i < this->ObfuscationLayers; i++)
	{
		//
		// "Randomly" pick an obfuscator to apply.
		//
		obfuscatorChoice = rand() % SCAST<INT>(Obfuscators::MAX);
		
		switch (obfuscatorChoice)
		{
			case SCAST<INT>(Obfuscators::Xor):
				finalPacket = RCAST<PBASE_PACKET>(this->ApplyXorPacket(finalPacket));
				pointersToFree.push_back(finalPacket);
				break;
		}
	}

	//
	// Send the magic constant.
	//
	success = SocketClient->SendPacket(RCAST<CHAR*>(CCAST<PDWORD>(&magicConstant)), sizeof(magicConstant));

	//
	// Send the packet.
	//
	success = SocketClient->SendPacket(RCAST<CHAR*>(finalPacket), finalPacket->PacketLength);

	//
	// Free each layer of obfuscation.
	//
	for (PVOID pointerToFree : pointersToFree)
	{
		free(pointerToFree);
	}
	
	return success;
}