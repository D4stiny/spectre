/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "PacketHandler.h"

typedef class PingPacketHandler : public PacketHandler
{
public:
    using PacketHandler::PacketHandler;
    NTSTATUS ProcessPacket (
        _In_ PBASE_PACKET FullPacket
        );
} PING_PACKET_HANDLER, *PPING_PACKET_HANDLER;

#define PING_PACKET_HANDLER_TAG DEFINE_TAG('hPpS')