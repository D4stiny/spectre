/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "ModuleManager.h"

/**
	Dispatches arguments to the module specified by the second argument.
	Arguments passed to modules are those only for that module.
	@param ArgumentCount - The number of arguments passed to the application.
	@param Arguments - The arguments passed to the application.
	@return Return code for the module. -1 if the module is not found.
*/
INT
ModuleManager::DispatchToModule (
	_In_ INT ArgumentCount,
	_In_ CHAR* Arguments[]
	)
{
	std::vector<std::string> vectorArguments;
	std::string moduleName;
	CLI_MODULE* selectedModule;
	ULONG i;
	INT returnValue;

	moduleName = "help";
	selectedModule = NULL;
	returnValue = -1;

	//
	// First, let's put our arguments in a vector to make our lives easier.
	//
	for (i = 0; i < ArgumentCount; i++)
	{
		vectorArguments.push_back(Arguments[i]);
	}

	//
	// Only if we have enough parameters to extract module information should we process
	// the arguments further, otherwise default to the HelpModule.
	//
	if (ArgumentCount >= 2)
	{
		//
		// The module name should always be the second argument.
		//
		moduleName = vectorArguments[1];

		//
		// Ensure the string is lowercase.
		//
		for (i = 0; i < moduleName.size(); i++)
		{
			moduleName[i] = std::tolower(moduleName[i]);
		}

		//
		// With the module name extracted, we don't need the first two arguments.
		//
		vectorArguments.erase(vectorArguments.begin(), vectorArguments.begin() + 2);
	}
	
	//
	// Get ready for the if/else train!
	//
	if (moduleName == "configure")
	{
		selectedModule = new ConfigurationWizardModule(vectorArguments);
	}
	else if (moduleName == "ping")
	{
		selectedModule = new PingModule(vectorArguments);
	}
	else if (moduleName == "command")
	{
		selectedModule = new CommandModule(vectorArguments);
	}
	else
	{
		selectedModule = new HelpModule(vectorArguments);
	}

	//
	// Process the arguments.
	//
	if (selectedModule)
	{
		returnValue = selectedModule->ProcessArguments();
	}

	delete selectedModule;
	return returnValue;
}