/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"

typedef class CLIModule
{
protected:
	//
	// Module arguments.
	//
	std::vector<std::string> ModuleArguments;
public:
	CLIModule (
		_In_ std::vector<std::string> Arguments
		);
	~CLIModule() {};

	virtual INT ProcessArguments (
		VOID
		) = 0;
} CLI_MODULE, *PCLI_MODULE;