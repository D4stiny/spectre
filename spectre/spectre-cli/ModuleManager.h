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
#include "ConfigurationWizardModule.h"
#include "PingModule.h"
#include "CommandModule.h"

typedef class ModuleManager
{
public:
	ModuleManager () {};
	~ModuleManager() {};

	INT DispatchToModule (
		_In_ INT ArgumentCount,
		_In_ CHAR* Arguments[]
		);
} MODULE_MANAGER, *PMODULE_MANAGER;