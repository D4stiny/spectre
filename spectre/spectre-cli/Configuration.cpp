/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "Configuration.h"

/**
	Constructor for the configurator.
*/
Configuration::Configuration (
	_In_ std::string ConfigName
	)
{
	this->ConfigFileName = ConfigName + ".cfg";
}

/**
	Free dynamically allocated resources.
*/
Configuration::~Configuration (
	VOID
	)
{
}

/**
	Read the config file as JSON.
	@return Whether or not reading the config file was successful.
*/
BOOLEAN
Configuration::ReadConfig (
	VOID
	)
{
	std::ifstream configFile(this->ConfigFileName);
	std::string configContent;

	//
	// Make sure we actually opened the config file.
	//
	if (configFile.is_open() == FALSE)
	{
		DBGPRINT("Configuration!ReadConfig: Failed to read config file, does it exist?");
		return FALSE;
	}

	//
	// Read the config file into a string.
	//
	configContent = std::string((std::istreambuf_iterator<char>(configFile)), std::istreambuf_iterator<char>());

	//
	// Parse the JSON.
	//
	this->ConfigRoot = json::parse(configContent);
	if (this->ConfigRoot == NULL)
	{
		DBGPRINT("Configuration!ReadConfig: Could not parse JSON from config file, is it corrupted?");
		return FALSE;
	}

	return TRUE;
}

/**
	Write the current config to the disk.
	@return Whether or not writing the config was successful.
*/
BOOLEAN
Configuration::WriteConfig (
	VOID
	)
{
	std::ofstream configFile(this->ConfigFileName);
	std::string configContent;

	//
	// Make sure we actually opened the config file.
	//
	if (configFile.is_open() == FALSE)
	{
		DBGPRINT("Configuration!WriteConfig: Failed to write to the config file.");
		return FALSE;
	}

	//
	// Convert the JSON to a string.
	//
	configContent = this->ConfigRoot.dump();

	//
	// Write the string to the config file.
	//
	configFile << configContent;
	configFile.close();

	return TRUE;
}