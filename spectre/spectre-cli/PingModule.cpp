/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "PingModule.h"

/**
    Ping unconfirmed ports to determine if they are infected.
    @return TRUE if valid config file specified, FALSE otherwise.
*/
INT
PingModule::ProcessArguments (
    VOID
    )
{
    BOOLEAN success;
    std::string input;
    PCONFIGURATION config;
    std::string configFileName;
    PSPECTRE_CLIENT spectreClient;

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
        HelpModule::PrintPingUsage();
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

    //
    // Scan the ports specified in the config.
    //
    success = spectreClient->ScanPorts();
    if (success == FALSE)
    {
        std::cout << "Failed to scan ports on the target machine." << std::endl;
        goto Exit;
    }

    std::cout << "Finished scanning ports." << std::endl;
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