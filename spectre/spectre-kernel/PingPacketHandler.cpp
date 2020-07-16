/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "PingPacketHandler.h"

/**
    Process a PING packet.
    @param FullPacket - Pointer to the full malicious packet.
    @return Whether or not processing was successful.
*/
NTSTATUS
PingPacketHandler::ProcessPacket (
    _In_ PBASE_PACKET FullPacket
    )
{
    MAGIC_BASE_PACKET responsePacket;
    
    //
    // For pings, we don't need to touch the packet.
    //
    UNREFERENCED_PARAMETER(FullPacket);

    DBGPRINT("PingPacketHandler!ProcessPacket: Received PING packet!");

    //
    // For pings, just respond with another ping packet.
    //
    responsePacket.Magic = PACKET_MAGIC;
    responsePacket.Base.Type = PACKET_TYPE::Ping;
    responsePacket.Base.PacketLength = sizeof(responsePacket);

    //
    // Send the response.
    //
    this->PacketDispatch->SendBuffer(&responsePacket, sizeof(responsePacket));

    return STATUS_SUCCESS;
}