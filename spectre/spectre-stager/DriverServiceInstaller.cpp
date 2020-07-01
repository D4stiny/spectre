/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * The function named "SetPrivilege" in this file
 * is excluded from this license.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "DriverServiceInstaller.h"

//
// Referenced from https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
//
BOOLEAN SetPrivilege (
    _In_ HANDLE hToken,          // access token handle
    _In_ LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    _In_ BOOL bEnablePrivilege   // to enable or disable privilege
    )
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        DBGPRINT("SetPrivilege: LookupPrivilegeValue failed with error %i.", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        DBGPRINT("SetPrivilege: AdjustTokenPrivileges failed with error %i.", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        DBGPRINT("SetPrivilege: The token does not have the specified privilege.", GetLastError());
        return FALSE;
    }

    return TRUE;
}

/**
    Adjust the current process token to allow for loading drivers.
    @return Whether or not we adjusted our privilege successfully.
*/
BOOLEAN
DriverServiceInstaller::EnableLoadDriverPrivilege (
    VOID
    )
{
    BOOLEAN result;
    HANDLE currentProcessToken;

    result = FALSE;
    currentProcessToken = NULL;

    //
    // If we already adjusted, don't do it again.
    //
    if (this->PrivilegeAdjusted)
    {
        result = TRUE;
        goto Exit;
    }

    //
    // Open a handle to our own token to modify it.
    //
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &currentProcessToken) == FALSE)
    {
        DBGPRINT("DriverServiceInstaller!EnableLoadDriverPrivilege: Failed to open the current process's token with error %i.", GetLastError());
        goto Exit;
    }

    //
    // Set our token to allow for calls to NtLoadDriver.
    //
    if (SetPrivilege(currentProcessToken, SE_LOAD_DRIVER_NAME, true) == FALSE)
    {
        DBGPRINT("DriverServiceInstaller!EnableLoadDriverPrivilege: Failed to adjust the privilege of our own token with error %i.", GetLastError());
        goto Exit;
    }

    result = TRUE;
    this->PrivilegeAdjusted = TRUE;
Exit:
    if (currentProcessToken != NULL)
    {
        CloseHandle(currentProcessToken);
    }
    return result;
}

/**
    Initialize default class members.
*/
VOID
DriverServiceInstaller::InitializeMembers (
    _In_ std::string DriverName
    )
{
    auto system32path = xorstr("\\system32\\drivers\\");
    auto ntLoadDriverName = xorstr("NtLoadDriver");
    auto ntUnloadDriverName = xorstr("NtUnloadDriver");
    auto registryBasePath = xorstr("System\\CurrentControlSet\\Services\\");

    this->DriverName = DriverName;
    this->DriverInstallPath = system32path.crypt_get() + DriverName + ".sys";
    this->DriverRegistryPath = registryBasePath.crypt_get() + DriverName;
    this->NtLoadDriver = RCAST<NtLoadDriver_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), ntLoadDriverName.crypt_get()));
    this->NtUnloadDriver = RCAST<NtUnloadDriver_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), ntUnloadDriverName.crypt_get()));
    printf("Driver Name = %s\n", DriverName.c_str());
    system32path.crypt();
    ntLoadDriverName.crypt();
    ntUnloadDriverName.crypt();
    registryBasePath.crypt();
}

/**
    Initializes default class members.
*/
DriverServiceInstaller::DriverServiceInstaller (
    _In_ std::string DriverName
	)
{
    this->InitializeMembers(DriverName);
}

/**
    Wrapper around default constructor. Generates a random driver name between 5 and 15 characters.
*/
DriverServiceInstaller::DriverServiceInstaller (
	VOID
	)
{
    std::string randomDriverName;
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";

    //
    // Insecure but okay for our uses.
    //
    srand(time(NULL));

    //
    // Generate random string with minimum length of 5 characters.
    //
    for (int i = 0; i < (rand() % 10) + 5; ++i) {
        randomDriverName += alphabet[rand() % (sizeof(alphabet) - 1)];
    }

    this->InitializeMembers(randomDriverName);
}

/**
    Installs a driver service entry in the registry.
    @return Whether or not installation was successful.
*/
BOOLEAN
DriverServiceInstaller::RegistryInstallDriver (
    VOID
    )
{
    LSTATUS status;
    HKEY driverRegistryKey;
    HKEY driverRegistryParametersKey;
    std::string driverSystemPath;
    std::string registryParametersPath;
    DWORD DriverType;
    DWORD DriverErrorControl;
    DWORD DriverStart;

    status = ERROR_SUCCESS;
    driverSystemPath = "\\SystemRoot" + this->DriverInstallPath;
    registryParametersPath = this->DriverRegistryPath + "\\Parameters";
    DriverType = 1; // Driver
#ifdef _DEBUG
    DriverErrorControl = 1; // Normal
#else
    DriverErrorControl = 0; // Ignore
#endif
    DriverStart = 2; // Auto start

    //
    // Create the service registry key for our driver.
    //
    status = RegCreateKeyExA(HKEY_LOCAL_MACHINE, this->DriverRegistryPath.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &driverRegistryKey, 0);
    if (NT_SUCCESS(status) == FALSE)
    {
        DBGPRINT("DriverServiceInstaller!RegistryInstallDriver: Failed to create driver registry key with status 0x%X.", status);
        goto Exit;
    }

    //
    // Create the parameters for our filter.
    //
    status = RegCreateKeyExA(HKEY_LOCAL_MACHINE, registryParametersPath.c_str(), 0, NULL, 0, KEY_ALL_ACCESS, NULL, &driverRegistryParametersKey, 0);
    if (NT_SUCCESS(status) == FALSE)
    {
        DBGPRINT("DriverServiceInstaller!RegistryInstallDriver: Failed to create driver parameters registry key with status 0x%X.", status);
        goto Exit;
    }

    //
    // Set the path of the driver binary.
    //
    status = RegSetValueExA(driverRegistryKey, "ImagePath", 0, REG_EXPAND_SZ, RCAST<CONST BYTE*>(driverSystemPath.c_str()), SCAST<DWORD>(driverSystemPath.length()));
    if (NT_SUCCESS(status) == FALSE)
    {
        DBGPRINT("DriverServiceInstaller!RegistryInstallDriver: Failed to write the driver ImagePath with status 0x%X.", status);
        goto Exit;
    }

    //
    // Write the DWORDs related to the service entry.
    //
    status = RegSetValueExA(driverRegistryKey, "Type", 0, REG_DWORD, RCAST<CONST BYTE*>(&DriverType), sizeof(DWORD));
    if (NT_SUCCESS(status) == FALSE)
    {
        DBGPRINT("DriverServiceInstaller!RegistryInstallDriver: Failed to write the driver type with status 0x%X.", status);
        goto Exit;
    }

    status = RegSetValueExA(driverRegistryKey, "ErrorControl", 0, REG_DWORD, RCAST<CONST BYTE*>(&DriverErrorControl), sizeof(DWORD));
    if (NT_SUCCESS(status) == FALSE)
    {
        DBGPRINT("DriverServiceInstaller!RegistryInstallDriver: Failed to write the driver error control with status 0x%X.", status);
        goto Exit;
    }

    status = RegSetValueExA(driverRegistryKey, "Start", 0, REG_DWORD, RCAST<CONST BYTE*>(&DriverStart), sizeof(DWORD));
    if (NT_SUCCESS(status) == FALSE)
    {
        DBGPRINT("DriverServiceInstaller!RegistryInstallDriver: Failed to write the driver start type with status 0x%X.", status);
        goto Exit;
    }
Exit:
    if (driverRegistryKey != NULL)
    {
        RegCloseKey(driverRegistryKey);
    }
    //
    // If we failed to install the driver, we need to make sure the registry key is deleted.
    //
    if (status != ERROR_SUCCESS)
    {
        //
        // If this fails too... tough luck lol
        //
        this->RegistryRemoveDriver();
    }
    return status == ERROR_SUCCESS;
}

/**
    Removes the registry entry for the driver.
    @return Whether or not removal was successful.
*/
BOOLEAN
DriverServiceInstaller::RegistryRemoveDriver (
    VOID
    )
{
    LSTATUS status;

    //
    // Remove the key recursively.
    //
    status = SHDeleteKeyA(HKEY_LOCAL_MACHINE, this->DriverRegistryPath.c_str());

    return status == ERROR_SUCCESS;
}

/**
    Installs the driver on the filesystem and registry.
    @param DriverContent - The bytes of the driver to install.
    @param DriverContentSize - The size in bytes of the DriverContent array.
    @return Whether or not installation was successful.
*/
BOOLEAN
DriverServiceInstaller::InstallDriver (
    _In_ unsigned char DriverContent[],
    _In_ DWORD DriverContentSize
    )
{
    BOOLEAN result;
    std::ofstream driverFile;
    std::string driverFullPath;

    result = FALSE;
    driverFullPath = "C:\\Windows" + this->DriverInstallPath;

    //
    // Before putting the file on disk, let's try and set up the registry.
    //
    result = this->RegistryInstallDriver();
    if (result == FALSE)
    {
        DBGPRINT("DriverServiceInstaller!InstallDriver: Failed to install the driver into the registry, aborting.");
        goto Exit;
    }

    //
    // Write the driver to the disk.
    //
    driverFile.open(driverFullPath, std::ios::binary);
    driverFile.write(RCAST<CONST CHAR*>(DriverContent), DriverContentSize);
    driverFile.close();

    result = TRUE;
Exit:
    return result;
}

/**
    Starts the driver using NtLoadDriver.
    @return Whether or not starting the driver was successful.
*/
BOOLEAN
DriverServiceInstaller::StartDriver (
    VOID
    )
{
    NTSTATUS status;
    UNICODE_STRING driverRegistryUnicodeString;
    std::wstring driverRegistryWidePath;

    status = STATUS_FAILED;
    driverRegistryWidePath = L"\\Registry\\Machine\\" + std::wstring(this->DriverRegistryPath.begin(), this->DriverRegistryPath.end());

    //
    // We need to enable load driver privilege to call NtLoadDriver.
    //
    if (this->EnableLoadDriverPrivilege() == FALSE)
    {
        DBGPRINT("DriverServiceInstaller!StartDriver: Failed to enable LoadDriver privilege, aborting.");
        goto Exit;
    }

    //
    // Fill out the unicode string structure.
    //
    driverRegistryUnicodeString.Buffer = RCAST<WORD*>(CCAST<WCHAR*>(driverRegistryWidePath.c_str()));
    driverRegistryUnicodeString.Length = SCAST<WORD>(driverRegistryWidePath.length() * 2);
    driverRegistryUnicodeString.MaximumLength = SCAST<WORD>(driverRegistryWidePath.length() * 2);

    //
    // Load the driver.
    //
    status = this->NtLoadDriver(&driverRegistryUnicodeString);
    if (NT_SUCCESS(status) == FALSE)
    {
        DBGPRINT("DriverServiceInstaller!StartDriver: NtLoadDriver failed with status 0x%X.", status);
        goto Exit;
    }
Exit:
    return NT_SUCCESS(status);
}

/**
    Stop the driver.
    @return TRUE if stopping was successful, otherwise FALSE.
*/
BOOLEAN
DriverServiceInstaller::StopDriver (
    VOID
    )
{
    NTSTATUS status;
    UNICODE_STRING driverRegistryUnicodeString;
    std::wstring driverRegistryWidePath;

    status = STATUS_FAILED;
    driverRegistryWidePath = L"\\Registry\\Machine\\" + std::wstring(this->DriverRegistryPath.begin(), this->DriverRegistryPath.end());

    //
    // We need to enable load driver privilege to call NtLoadDriver.
    //
    if (this->EnableLoadDriverPrivilege() == FALSE)
    {
        DBGPRINT("DriverServiceInstaller!StopDriver: Failed to enable LoadDriver privilege, aborting.");
        goto Exit;
    }

    //
    // Fill out the unicode string structure.
    //
    driverRegistryUnicodeString.Buffer = RCAST<WORD*>(CCAST<WCHAR*>(driverRegistryWidePath.c_str()));
    driverRegistryUnicodeString.Length = SCAST<WORD>(driverRegistryWidePath.length() * 2);
    driverRegistryUnicodeString.MaximumLength = SCAST<WORD>(driverRegistryWidePath.length() * 2);

    //
    // Load the driver.
    //
    status = this->NtUnloadDriver(&driverRegistryUnicodeString);
    if (NT_SUCCESS(status) == FALSE)
    {
        DBGPRINT("DriverServiceInstaller!StopDriver: NtUnloadDriver failed with status 0x%X.", status);
        goto Exit;
    }
Exit:
    return NT_SUCCESS(status);
}

/**
    Remove the driver from the registry and filesystem.
    @return Whether or not removal was successful.
*/
BOOLEAN
DriverServiceInstaller::UninstallDriver (
    VOID
    )
{
    BOOLEAN result;
    std::string driverFullPath;

    driverFullPath = "C:\\Windows" + this->DriverInstallPath;

    result = this->RegistryRemoveDriver();
    if (result == FALSE)
    {
        DBGPRINT("DriverServiceInstaller!UninstallDriver: Failed to remove the driver from the registry.");
        goto Exit;
    }

    if (std::remove(driverFullPath.c_str()) != 0)
    {
        DBGPRINT("DriverServiceInstaller!UninstallDriver: Failed to remove the driver from the filesystem.");
        goto Exit;
    }
Exit:
    return result;
}
