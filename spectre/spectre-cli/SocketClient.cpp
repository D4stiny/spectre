/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "SocketClient.h"

/**
	Initialize basic class members.
	@param IPAddress - The target machine IP Address.
	@param ReceiveRetryCount - The maximum number of times to retry a receive request.
	@param ConnectTimeoutSec - connect() timeout in seconds.
*/
SocketClient::SocketClient (
	_In_ std::string IPAddress,
	_In_ INT ReceiveRetryCount,
	_In_ INT ConnectTimeoutSec
	)
{
	this->TargetIP = IPAddress;
	this->MaxReceiveRetryCount = ReceiveRetryCount;
	this->ConnectTimeout = ConnectTimeoutSec;
	this->TargetSocket = INVALID_SOCKET;
}

/**
	Deconstructor for the Socket Client.
*/
SocketClient::~SocketClient (
	VOID
	)
{
	this->Disconnect();
}

/**
	Sets the blocking state of the socket.
	@param Blocking - TRUE if blocking should be enabled, FALSE otherwise.
	@return Whether or not setting the socket blocking state was successful.
*/
BOOLEAN
SocketClient::SetSocketBlocking (
	_In_ BOOLEAN Blocking
	)
{
	ULONG isBlocking;

	isBlocking = Blocking;

	if (ioctlsocket(this->TargetSocket, FIONBIO, &isBlocking) == SOCKET_ERROR)
	{
		DBGPRINT("SocketClient!SetSocketBlocking: Failed to set socket blocking state with error %i.", WSAGetLastError());
		return FALSE;
	}

	return TRUE;
}

/**
	Attempt to connect to the target asynchronously.
	@param Port - The port to connect to.
	@return Whether or not a connection was established successfully.
*/
BOOLEAN
SocketClient::AsyncConnect (
	_In_ std::string Port
	)
{
	INT result;
	BOOLEAN success;
	ADDRINFOA clientHints;
	PADDRINFOA resultAddresses;
	PADDRINFOA currentAddrInfo;
	timeval connectTimeout;
	fd_set writeCheck;
	fd_set exceptionCheck;

	//
	// Sanity check.
	//
	if (this->TargetSocket != INVALID_SOCKET)
	{
		printf("SocketClient!AsyncConnect: Attempting to connect to an already connected client.");
		return TRUE;
	}

	//
	// Initialize the hints about the type of connection we want.
	//
	memset(&clientHints, 0, sizeof(clientHints));
	clientHints.ai_family = AF_INET;
	clientHints.ai_socktype = SOCK_STREAM;
	clientHints.ai_protocol = IPPROTO_TCP;

	//
	// Set our connection timeouts.
	//
	connectTimeout.tv_sec = this->ConnectTimeout;
	connectTimeout.tv_usec = 0;

	//
	// Attempt to obtain the addrinfo structure for the target.
	//
	result = getaddrinfo(this->TargetIP.c_str(), Port.c_str(), &clientHints, &resultAddresses);
	if (result != 0)
	{
		DBGPRINT("SocketClient!AsyncConnect: Failed to query addrinfo about target with error %i.", WSAGetLastError());
		goto Exit;
	}

	//
	// Enumerate every returned address until once succeeds.
	//
	for (currentAddrInfo = resultAddresses; currentAddrInfo != NULL && this->TargetSocket == INVALID_SOCKET; currentAddrInfo = currentAddrInfo->ai_next)
	{
		//
		// Create the socket for the addrinfo.
		//
		this->TargetSocket = socket(currentAddrInfo->ai_family, currentAddrInfo->ai_socktype, currentAddrInfo->ai_protocol);
		if (this->TargetSocket == INVALID_SOCKET)
		{
			closesocket(this->TargetSocket);
			this->TargetSocket = INVALID_SOCKET;
			continue;
		}

		//
		// Set the socket into a non-blocking state.
		//
		success = this->SetSocketBlocking(FALSE);
		if (success == FALSE)
		{
			closesocket(this->TargetSocket);
			this->TargetSocket = INVALID_SOCKET;
			result = 1;
			continue;
		}

		//
		// Connect to the target.
		//
		result = connect(this->TargetSocket, currentAddrInfo->ai_addr, SCAST<INT>(currentAddrInfo->ai_addrlen));
		if (result == SOCKET_ERROR)
		{
			//
			// If our error isn't WSAEWOULDBLOCK, we couldn't connect to the target.
			//
			if (WSAGetLastError() != WSAEWOULDBLOCK)
			{
				closesocket(this->TargetSocket);
				this->TargetSocket = INVALID_SOCKET;
				continue;
			}

			FD_ZERO(&writeCheck);
			FD_ZERO(&exceptionCheck);
			FD_SET(this->TargetSocket, &writeCheck);
			FD_SET(this->TargetSocket, &exceptionCheck);

			//
			// Check for write ability and exceptions.
			//
			result = select(0, NULL, &writeCheck, &exceptionCheck, &connectTimeout);
			if (result <= 0)
			{
				DBGPRINT("SocketClient!AsyncConnect: Connecting to port %s failed due to timeout or error.", Port.c_str());
				closesocket(this->TargetSocket);
				this->TargetSocket = INVALID_SOCKET;
				continue;
			}

			if (FD_ISSET(this->TargetSocket, &exceptionCheck))
			{
				DBGPRINT("SocketClient!AsyncConnect: Connecting to port %s failed due to a socket exception.", Port.c_str());
				closesocket(this->TargetSocket);
				this->TargetSocket = INVALID_SOCKET;
				continue;
			}
		}

		//
		// If we got this far, the connection was successful!
		//
		success = this->SetSocketBlocking(FALSE);
		if (success == FALSE)
		{
			closesocket(this->TargetSocket);
			this->TargetSocket = INVALID_SOCKET;
			result = 1;
			continue;
		}
	}

	if (this->TargetSocket == INVALID_SOCKET)
	{
		DBGPRINT("SocketClient!AsyncConnect: All attempts at connecting to port %s failed.", Port.c_str());
		result = SOCKET_ERROR;
		goto Exit;
	}
Exit:
	if (resultAddresses)
	{
		freeaddrinfo(resultAddresses);
	}
	//
	// If we successfully opened a connect, delay for a bit to allow the rootkit to hook the socket.
	//
	if (result == 0)
	{
		Sleep(CONNECT_DELAY);
	}
	return result == 0;
}

/**
	Disconnect from the target.
	@return Whether or not we were able to successfully disconnect from the server.
*/
BOOLEAN
SocketClient::Disconnect (
	VOID
	)
{
	SOCKET currentSocket;

	currentSocket = this->TargetSocket;
	if (currentSocket != INVALID_SOCKET)
	{
		this->TargetSocket = INVALID_SOCKET;
		shutdown(currentSocket, SD_SEND);
		return closesocket(currentSocket) == 0;
	}
	return FALSE;
}

/**
	Send a packet to the socket.
	@param InputBuffer - Buffer to send to target.
	@param InputBufferSize - The size (in bytes) of the InputBuffer.
	@return Whether or not sending the packet was successful.
*/
BOOLEAN
SocketClient::SendPacket (
	_In_ CHAR* InputBuffer,
	_In_ ULONG InputBufferSize
	)
{
	INT result;
	
	result = send(this->TargetSocket, InputBuffer, InputBufferSize, 0);
	if (result == SOCKET_ERROR)
	{
		DBGPRINT("SocketClient!SendPacket: Failed to send the packet with error %i.", WSAGetLastError());
		return FALSE;
	}

	return TRUE;
}

/**
	Receive bytes from the socket.
	@param OutputBuffer - The buffer to store received bytes in.
	@return Whether or not receiving data was successful.
*/
BOOLEAN
SocketClient::ReceivePacket (
	_Inout_ std::vector<BYTE>& OutputBuffer
	)
{
	INT result;
	INT invalidResponseOccurence;
	CHAR tempBuffer[256];

	result = 0;
	invalidResponseOccurence = 0;

	//
	// Keep retrying until we hit the max retry count or we don't have any data to receive.
	//
	do
	{
		//
		// Attempt to receive up to 256 bytes.
		//
		result = recv(this->TargetSocket, tempBuffer, sizeof(tempBuffer), 0);
		if (result == SOCKET_ERROR)
		{
			invalidResponseOccurence++;
			DBGPRINT("SocketClient!ReceivePacket: Failed to receive data from the socket with error %i.", WSAGetLastError());
			continue;
		}

		//
		// Copy over the results into the response vector.
		//
		std::copy(tempBuffer, RCAST<CHAR*>(RCAST<ULONG64>(tempBuffer) + result), std::back_inserter(OutputBuffer));

		//
		// If we received less than the max of the tempBuffer, there is no more data.
		//
		if (result != sizeof(tempBuffer))
		{
			break;
		}
	} while (result != 0 && invalidResponseOccurence < this->MaxReceiveRetryCount);

	return result >= 0;
}

/**
	Set the send timeout for the socket.
	@param TimeoutMs - The time to wait for send operations (in ms).
	@return Whether or not setting the send timeout was successful.
*/
BOOLEAN
SocketClient::SetSendTimeout (
	_In_ DWORD TimeoutMs
	)
{
	INT result;

	//
	// Set the send timeout socket option.
	//
	result = setsockopt(this->TargetSocket, SOL_SOCKET, SO_SNDTIMEO, RCAST<CHAR*>(&TimeoutMs), sizeof(TimeoutMs));
	if (result == SOCKET_ERROR)
	{
		DBGPRINT("SocketClient!SetSendTimeout: Failed to set send timeout with error %i.", WSAGetLastError());
		return FALSE;
	}
	
	return TRUE;
}

/**
	Set the receive timeout for the socket.
	@param TimeoutMs - The time to wait for send operations (in ms).
	@return Whether or not setting the receive timeout was successful.
*/
BOOLEAN
SocketClient::SetReceiveTimeout (
	_In_ DWORD TimeoutMs
	)
{
	INT result;

	//
	// Set the send timeout socket option.
	//
	result = setsockopt(this->TargetSocket, SOL_SOCKET, SO_RCVTIMEO, RCAST<CHAR*>(&TimeoutMs), sizeof(TimeoutMs));
	if (result == SOCKET_ERROR)
	{
		DBGPRINT("SocketClient!SetSendTimeout: Failed to set receive timeout with error %i.", WSAGetLastError());
		return FALSE;
	}
	
	return TRUE;
}