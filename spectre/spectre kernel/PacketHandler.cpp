/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "PacketHandler.h"

/**
    Populate the necessary members in the PacketHandler class.
    @param Dispatcher - Used for sending/receiving packets and dispatching sub-packets.
*/
PacketHandler::PacketHandler (
    _In_ PPACKET_DISPATCH Dispatcher
    )
{
    this->PacketDispatch = Dispatcher;
}