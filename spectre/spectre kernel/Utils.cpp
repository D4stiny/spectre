/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "Utils.h"

/**
	Determine the address and size of a kernel module's next executable section.
	@param ImageBase - Image base of the kernel module.
	@param ExecSectionBase - Caller-allocated variable to indicate the first section to start searching from and store the next executable section base.
	@param ExecSectionSize - Caller-allocated variable to store the next executable section size.
	@return Status of the section search.
*/
NTSTATUS
Utilities::FindNextExecSection (
	_In_ PVOID ImageBase,
	_Inout_ PVOID* ExecSectionBase,
	_Inout_ SIZE_T* ExecSectionSize
	)
{
	NTSTATUS status;
	PIMAGE_DOS_HEADER driverDosHeader;
	PIMAGE_NT_HEADERS_C driverNtHeader;
	PIMAGE_SECTION_HEADER driverSectionHeader;
	BOOLEAN foundStartSectionBase;
	ULONG i;
	PVOID currentSectionBase;

	status = STATUS_SUCCESS;
	*ExecSectionSize = 0;
	foundStartSectionBase = FALSE;

	//
	// Check if a starting section was specified. If not, return the first section.
	//
	if (*ExecSectionBase == NULL)
	{
		foundStartSectionBase = TRUE;
	}

	driverDosHeader = RCAST<PIMAGE_DOS_HEADER>(ImageBase);
	if (driverDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		DBGPRINT("Utilities!FindModuleTextSection: The image has an invalid DOS Header Magic value.");
		status = STATUS_INVALID_ADDRESS;
		goto Exit;
	}

	driverNtHeader = RCAST<PIMAGE_NT_HEADERS_C>(RCAST<ULONG_PTR>(driverDosHeader) + driverDosHeader->e_lfanew);
	if (driverNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		DBGPRINT("Utilities!FindModuleTextSection: The image has an invalid NT Header Magic value.");
		status = STATUS_INVALID_ADDRESS;
		goto Exit;
	}

	driverSectionHeader = IMAGE_FIRST_SECTION(driverNtHeader);

	//
	// Enumerate each section of the driver for the ".text" section.
	//
	for (i = 0; i < driverNtHeader->FileHeader.NumberOfSections; i++)
	{
		currentSectionBase = RCAST<PVOID>(RCAST<ULONG_PTR>(driverDosHeader) + driverSectionHeader[i].VirtualAddress);
		if (foundStartSectionBase == FALSE && currentSectionBase == *ExecSectionBase)
		{
			foundStartSectionBase = TRUE;
			continue;
		}
		else if (foundStartSectionBase && FlagOn(driverSectionHeader[i].Characteristics, IMAGE_SCN_MEM_EXECUTE))
		{
			*ExecSectionBase = currentSectionBase;
			*ExecSectionSize = driverSectionHeader[i].SizeOfRawData;
			break;
		}
	}
Exit:
	return status;
}

/**
	Search for a Pattern of bytes that match the Mask.
	@param Address - The address to begin the search at.
	@param Length - The number of bytes to compare.
	@param Pattern - The pattern to match.
	@param Mask - The mask to apply to the pattern.
	@return NULL if not found. Otherwise, a pointer to the first match.
*/
PVOID
Utilities::FindPattern (
	_In_ CONST PVOID Address,
	_In_ CONST SIZE_T Length,
	_In_ CONST CHAR* Pattern,
	_In_ CONST CHAR* Mask
	)
{
	for (auto i = 0; i < Length; i++)
		if (Utilities::CompareData(RCAST<CONST CHAR*>(RCAST<ULONG_PTR>(Address) + i), Pattern, Mask))
			return RCAST<PVOID>(RCAST<ULONG_PTR>(Address) + i);
	return NULL;
}

/**
	Compare data against a pattern and mask.
	@param Data - The data to compare.
	@param Pattern - The pattern to compare against.
	@param Mask - The mask to apply to the pattern.
	@return Whether or not the data fits the pattern and mask.
*/
BOOLEAN
Utilities::CompareData (
	_In_ CONST CHAR* Data,
	_In_ CONST CHAR* Pattern,
	_In_ CONST CHAR* Mask
	)
{
	for (; *Mask; ++Mask, ++Data, ++Pattern)
		if (*Mask == 'x' && *Data != *Pattern)
			return FALSE;
	return (*Mask) == 0;
}

/**
	Enumerate executable sections in ImpersonateDriver and find a "jmp rcx" gadget.
	If found, create a new thread at that gadget location, to spoof the start address of the thread.
	Set the first argument (rcx register) passed to the thread to be the actual thread function, which the gadget willl jump to.
*/
BOOLEAN
Utilities::CreateHiddenThread (
	_In_ PDRIVER_OBJECT ImpersonateDriver,
	_In_ PVOID ThreadFunction
	)
{
	NTSTATUS status;
	HANDLE threadHandle;
	PVOID jmpRcxGadget;
	PVOID currentExecutableSection;
	SIZE_T currentExecutableSectionSize;

	jmpRcxGadget = NULL;
	currentExecutableSection = NULL;
	currentExecutableSectionSize = 0;

	//
	// Enumerate each executable of the ImpersonateDriver to look for a "jmp rcx" (0xFF, 0xE1) gadget.
	//
	while (NT_SUCCESS(Utilities::FindNextExecSection(ImpersonateDriver->DriverStart, &currentExecutableSection, &currentExecutableSectionSize)) && jmpRcxGadget == NULL)
	{
		jmpRcxGadget = FindPattern(currentExecutableSection, currentExecutableSectionSize, "\xFF\xE1", "xx");
	}

	//
	// Check if we were able to find a gadget.
	//
	if (jmpRcxGadget == NULL)
	{
		DBGPRINT("Utilities!CreateHiddenThread: Failed to find a \"jmp rcx\" gadget in the driver %wZ.", ImpersonateDriver->DriverName);
		return FALSE;
	}

	//
	// Create a system thread on the "jmp rcx" gadget with the actual thread function as the first argument (rcx register).
	//
	status = PsCreateSystemThread(&threadHandle, 0, NULL, 0, NULL, RCAST<PKSTART_ROUTINE>(jmpRcxGadget), ThreadFunction);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("Utilities!CreateHiddenThread: Failed to create system thread with status 0x%X.", status);
		return FALSE;
	}
	
	ZwClose(threadHandle);
	return TRUE;
}

/**
	Get the system module information for a module specified by the name ModuleName.
	@param ModuleName - The name of the target system module.
	@return The target system module information. Will be empty if not found.
*/
CONST RTL_PROCESS_MODULE_INFORMATION
Utilities::GetDriverModule (
	_In_ CONST CHAR* ModuleName
	)
{
	NTSTATUS status;
	RTL_PROCESS_MODULE_INFORMATION driverModuleInformation;
	RTL_PROCESS_MODULE_INFORMATION currentModule;
	PRTL_PROCESS_MODULES systemModuleList;
	ULONG neededSize;
	ULONG i;

	memset(&driverModuleInformation, 0, sizeof(driverModuleInformation));
	neededSize = 0;

	//
	// Query the bytes required to query system modules.
	//
	ZwQuerySystemInformation(SystemModuleInformation, &neededSize, 0, &neededSize);

	//
	// Allocate space for modules.
	//
	systemModuleList = RCAST<PRTL_PROCESS_MODULES>(ExAllocatePool(NonPagedPoolNx, neededSize));
	if (systemModuleList == NULL)
	{
		DBGPRINT("Utilities!GetDriverModule: Failed to allocate space for system module list.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}

	//
	// Query the system modules.
 	//
	status = ZwQuerySystemInformation(SystemModuleInformation, systemModuleList, neededSize, NULL);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("Utilities!GetDriverModule: Failed to query the system module list with status 0x%X.", status);
		goto Exit;
	}

	//
	// Enumerate each system module for a match.
	//
	for (i = 0; i < systemModuleList->NumberOfModules; i++)
	{
		currentModule = systemModuleList->Modules[i];
		if(strstr(RCAST<CONST CHAR*>(currentModule.FullPathName), ModuleName) != NULL)
		{
			driverModuleInformation = currentModule;
			break;
		}
	}
Exit:
	if (NT_SUCCESS(status) == FALSE && systemModuleList)
	{
		ExFreePool(systemModuleList);
	}
	return driverModuleInformation;
}