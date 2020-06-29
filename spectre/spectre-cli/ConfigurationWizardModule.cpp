/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "ConfigurationWizardModule.h"

/**
    Prompt the user to enter configuration values.
    @return TRUE if successfully generated config file, otherwise FALSE.
*/
INT
ConfigurationWizardModule::ProcessArguments (
    VOID
    )
{
    BOOLEAN success;
    std::string input;
    PCONFIGURATION config;
    std::string configFileName;

    success = FALSE;
    config = NULL;

    //
    // The first argument for the module must be the config
    // file name.
    //
    if (this->ModuleArguments.size() != 1)
    {
        std::cout << "Incorrect usage:" << std::endl;
        HelpModule::PrintConfigureUsage();
        goto Exit;
    }

    configFileName = this->ModuleArguments[0];
    config = new Configuration(configFileName);

    std::cout << "Welcome to the Spectre Rootkit." << std::endl;
    std::cout << "This configuration wizard is designed to assist you with the generation of a configuration file." << std::endl;
    std::cout << "You need a configuration file to use any other module in the Spectre CLI." << std::endl;
    std::cout << std::endl;

    //
    // Attempt to write an empty config to ensure
    // we can write to the config file location.
    //
    success = config->WriteConfig();
    if (success == FALSE)
    {
        std::cout << "Failed to open configuration file \"" << configFileName << "\", aborting.";
        goto Exit;
    }

    //
    // Request input for each config value.
    //
    for (std::pair<std::string, CONFIG_VALUE> configValue : ConfigurationValues)
    {
        while (TRUE)
        {
            std::cout << "Please enter a value for \"" << configValue.second.FriendlyName << "\" (default: " << configValue.second.DefaultValue << "):" << std::endl;
            getline(std::cin, input);
            //
            // If no input is specified, use the default value.
            //
            if (input == "")
            {
                input = configValue.second.DefaultValue;
                std::cout << "No input entered, using default value \"" << input << "\"." << std::endl;
            }
            //
            // Validate the input to the config value regex.
            //
            success = std::regex_match(input, std::regex(configValue.second.FormatRegex));
            if (success)
            {
                break;
            }
            std::cout << "Input does not match the regex format \"" << configValue.second.FormatRegex << "\" for the config value." << std::endl;
        }
        config->WriteConfigValue<std::string>(configValue.first, input);
    }
    
    //
    // Save the config values.
    //
    success = config->WriteConfig();
    if (success == FALSE)
    {
        std::cout << "Failed to save configuration file \"" << configFileName << "\".";
        goto Exit;
    }

    std::cout << "Saved options to configuration \"" << configFileName << "\".";
    success = TRUE;
Exit:
    if (config)
    {
        delete config;
    }
    return success;
}
