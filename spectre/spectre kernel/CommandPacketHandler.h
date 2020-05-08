/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "PacketHandler.h"

//
// Timeout to execute a command (in ms).
//
#define DEFAULT_COMMAND_TIMEOUT 20000
//
// Maximum amount of bytes that can be returned to the client.
//
#define MAX_RESPONSE_SIZE 10000

typedef class CommandPacketHandler : public PacketHandler
{
public:
    using PacketHandler::PacketHandler;
    NTSTATUS ProcessPacket (
        _In_ PBASE_PACKET FullPacket
        );
} COMMAND_PACKET_HANDLER, * PCOMMAND_PACKET_HANDLER;

#define COMMAND_PACKET_HANDLER_TAG DEFINE_TAG('hCpS')
#define COMMAND_RESPONSE_TAG DEFINE_TAG('rCpS')