/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "PacketHandler.h"

typedef class XorPacketHandler : public PacketHandler
{
public:
    using PacketHandler::PacketHandler;
    NTSTATUS ProcessPacket (
        _In_ PBASE_PACKET FullPacket
        );
} XOR_PACKET_HANDLER, *PXOR_PACKET_HANDLER;

#define XOR_PACKET_HANDLER_TAG DEFINE_TAG('hXpS')