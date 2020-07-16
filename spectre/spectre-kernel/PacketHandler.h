/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "PacketDispatch.h"

typedef class PacketHandler
{
protected:
	//
	// The packet dispatcher is used for sending and receiving network messages.
	// It can also be used to dispatch a new packet.
	//
	PPACKET_DISPATCH PacketDispatch;
public:
	PacketHandler (
		_In_ PPACKET_DISPATCH Dispatcher
		);
	
	virtual NTSTATUS ProcessPacket (
		_In_ PBASE_PACKET FullPacket
		) = 0;
} PACKET_HANDLER, *PPACKET_HANDLER;