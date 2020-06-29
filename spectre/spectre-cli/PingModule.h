/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "Module.h"
#include "HelpModule.h"
#include "Configuration.h"
#include "SpectreClient.h"

typedef class PingModule : public CLIModule
{
public:
	using CLIModule::CLIModule;

	INT ProcessArguments (
		VOID
		);
} PING_MODULE, *PPING_MODULE;