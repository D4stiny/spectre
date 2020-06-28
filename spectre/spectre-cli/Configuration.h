/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "json.hpp"

using json = nlohmann::json;

//
// Configuration key for the target IP Address.
//
#define TARGET_IP_KEY "target_ip_address"
//
// Configuration key for the target ports.
//
#define TARGET_PORTS_KEY "target_ports"
//
// Configuration key for the confirmed ports.
//
#define CONFIRMED_PORTS_KEY "confirmed_ports"
//
// Configuration key for the connect timeout.
//
#define CONNECT_TIMEOUT_KEY "connect_timeout"
//
// Configuration key for the receive retry count.
//
#define RECEIVE_MAX_COUNT_KEY "receive_retry_count"
//
// Configuration key for the obfuscation count.
//
#define OBFUSCATION_COUNT_KEY "obfuscation_count"

typedef class Configuration
{
	//
	// The file name of the configuration file.
	//
	std::string ConfigFileName;
	//
	// The root object of the configuration file.
	//
	json ConfigRoot;
public:
	Configuration (
		_In_ std::string ConfigName
		);
	~Configuration (
		VOID
		);

	BOOLEAN ReadConfig (
		VOID
		);
	BOOLEAN WriteConfig (
		VOID
		);
	template <class T>
	BOOLEAN ReadConfigValue (
		_In_ std::string Key,
		_Inout_ T* Value
		)
	{
		//
		// Make sure the Key exists.
		//
		if (this->ConfigRoot.find(Key) == this->ConfigRoot.end())
		{
			DBGPRINT("Configuration!ReadConfigValue: Attempted to read key %s, it does not exist.", Key.c_str());
			return FALSE;
		}

		*Value = this->ConfigRoot[Key];
		return TRUE;
	}
	template <class T>
	VOID WriteConfigValue (
		_In_ std::string Key,
		_In_ T Value
		)
	{
		this->ConfigRoot[Key] = Value;
	}
} CONFIGURATION, *PCONFIGURATION;