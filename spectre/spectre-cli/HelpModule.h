/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "Module.h"

typedef class HelpModule : public CLIModule
{
public:
	using CLIModule::CLIModule;

	INT ProcessArguments (
		VOID
		);

	static VOID PrintHelpUsage (
		VOID
		);
	static VOID PrintConfigureUsage (
		VOID
		);
	static VOID PrintPingUsage (
		VOID
		);
	static VOID PrintCommandUsage (
		VOID
		);
} HELP_MODULE, *PHELP_MODULE;