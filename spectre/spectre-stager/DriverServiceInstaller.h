/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

typedef struct _UNICODE_STRING
{
	WORD Length;
	WORD MaximumLength;
	WORD* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef NTSTATUS(NTAPI* NtLoadDriver_t)
(
	__in PUNICODE_STRING DriverServiceName
	);

typedef NTSTATUS(NTAPI* NtUnloadDriver_t)
(
	__in PUNICODE_STRING DriverServiceName
	);

class DriverServiceInstaller
{
	BOOLEAN PrivilegeAdjusted;		// Whether or not we granted ourselves load driver privileges yet.
	std::string DriverName;			// The base name of the driver.
	std::string DriverInstallPath;	// The path to the driver binary.
	std::string DriverRegistryPath; // The path to the driver service registry entry.
	NtLoadDriver_t NtLoadDriver;
	NtUnloadDriver_t NtUnloadDriver;

	BOOLEAN EnableLoadDriverPrivilege (
		VOID
		);
	BOOLEAN RegistryInstallDriver (
		VOID
		);
	BOOLEAN RegistryRemoveDriver (
		VOID
		);
	VOID InitializeMembers (
		_In_ std::string DriverName
		);
public:
	DriverServiceInstaller (
		_In_ std::string DriverName
		);
	DriverServiceInstaller (
		VOID
		);

	BOOLEAN InstallDriver (
		_In_ unsigned char DriverContent[],
		_In_ DWORD DriverContentSize
		);
	BOOLEAN StartDriver (
		VOID
		);
	BOOLEAN StopDriver (
		VOID
		);
	BOOLEAN UninstallDriver (
		VOID
		);
};