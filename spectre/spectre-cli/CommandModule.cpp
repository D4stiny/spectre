/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "CommandModule.h"

/**
    Execute a command on the target machine.
    @return TRUE if valid config file specified, FALSE otherwise.
*/
INT
CommandModule::ProcessArguments (
    VOID
    )
{
    BOOLEAN success;
    std::string input;
    PCONFIGURATION config;
    std::string configFileName;
    PSPECTRE_CLIENT spectreClient;
    std::wstring command;
    std::string commandOutput;

    success = FALSE;
    config = NULL;
    spectreClient = NULL;

    //
    // The first argument for the module must be the config
    // file name.
    //
    if (this->ModuleArguments.size() != 1)
    {
        std::cout << "Incorrect usage:" << std::endl;
        HelpModule::PrintCommandUsage();
        goto Exit;
    }

    configFileName = this->ModuleArguments[0];
    config = new Configuration(configFileName);

    spectreClient = new SpectreClient(config);
    
    //
    // Initialize the Spectre Client's configuration.
    //
    success = spectreClient->InitializeConfig();
    if (success == FALSE)
    {
        std::cout << "Failed to initialize the Spectre Client." << std::endl;
        goto Exit;
    }

    std::cout << "Please enter the command to execute:" << std::endl;
    std::getline(std::wcin, command);
    std::wcout << L"Executing command \"" << command << L"\", please be patient as this can take a bit." << std::endl;

    //
    // Execute the command.
    //
    commandOutput = spectreClient->ExecuteCommand(command);
    if (commandOutput == "")
    {
        std::cout << "No output received." << std::endl;
        goto Exit;
    }

    std::cout << "Command executed with the output:" << std::endl << commandOutput << std::endl;
Exit:
    if (config)
    {
        delete config;
    }
    if (spectreClient)
    {
        delete spectreClient;
    }
    return TRUE;
}