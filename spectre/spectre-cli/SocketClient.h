/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"

//
// Amount of time to delay after connecting to the client.
// The rootkit needs a bit to hook into the socket.
//
#define CONNECT_DELAY 0

typedef class SocketClient
{
	//
	// The socket handle.
	//
	SOCKET TargetSocket;
	//
	// The IPv4 address of the target machine.
	//
	std::string TargetIP;
	//
	// The maximum number of times to retry a receive request.
	//
	INT MaxReceiveRetryCount;
	//
	// The number of seconds to wait for a socket to connect.
	//
	INT ConnectTimeout;
public:
	SocketClient (
		_In_ std::string IPAddress,
		_In_ INT ReceiveRetryCount,
		_In_ INT ConnectTimeoutSec
		);
	~SocketClient (
		VOID
		);

	BOOLEAN AsyncConnect (
		_In_ std::string Port
		);
	BOOLEAN Disconnect (
		VOID
		);
	BOOLEAN SendPacket (
		_In_ CHAR* InputBuffer,
		_In_ ULONG InputBufferSize
		);
	BOOLEAN ReceivePacket (
		_Inout_ std::vector<BYTE>& OutputBuffer
		);
	BOOLEAN SetSocketBlocking (
		_In_ BOOLEAN Blocking
		);
	BOOLEAN SetSendTimeout (
		_In_ DWORD TimeoutMs
		);
	BOOLEAN SetReceiveTimeout (
		_In_ DWORD TimeoutMs
		);
} SOCKET_CLIENT, *PSOCKET_CLIENT;