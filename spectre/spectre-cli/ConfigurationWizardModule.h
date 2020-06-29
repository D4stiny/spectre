/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "Configuration.h"
#include "Module.h"
#include "HelpModule.h"

typedef struct ConfigValue
{
	std::string FriendlyName;	// A friendly name for the config value, shown to the user.
	std::string DefaultValue;	// The default value for that config key.
	std::string FormatRegex;	// The regex input must match to be accepted.
} CONFIG_VALUE;
//
// Map of config values.
// The key is the value name written to disk.
// The first element of the pair is the "friendly name" for the config value.
// The second element of the pair is the default value of the configuration value.
//
CONST std::map<std::string, CONFIG_VALUE> ConfigurationValues = {
	{TARGET_IP_KEY, {"target IP address", "", "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"}},
	//
	// TODO: Add more common ports that are infected.
	//
	{TARGET_PORTS_KEY, {"ports to target separated by a comma", "135,5040,7680", "^[0-9,]+$"}},
	{CONNECT_TIMEOUT_KEY, {"timeout to connect to a port (in ms)", "1000", "^[0-9]+$"}},
	{RECEIVE_MAX_COUNT_KEY, {"number of times to retry failed responses", "3", "^[0-9]+$"}},
	{OBFUSCATION_COUNT_KEY, {"number of \"obfuscation layers\" to apply to outgoing packets", "2", "^[0-9]+$"}}
};

typedef class ConfigurationWizardModule : public CLIModule
{
public:
	using CLIModule::CLIModule;

	INT ProcessArguments (
		VOID
		);
} CONFIG_WIZARD_MODULE, *PCONFIG_WIZARD_MODULE;