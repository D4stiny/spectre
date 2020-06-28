/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "Module.h"

/**
	Initialize the generic CLI Module class.
	@param Arguments - Array of arguments passed to the module.
*/
CLIModule::CLIModule (
	_In_ std::vector<std::string> Arguments
	)
{
	this->ModuleArguments = Arguments;
}