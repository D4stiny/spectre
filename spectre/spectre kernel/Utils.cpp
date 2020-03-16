/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "Utils.h"

/**
	Determine the address and size of a kernel module's ".text" section.
	@param ImageBase - Image base of the kernel module.
	@param TextSectionBase - Caller-allocated variable to store the ".text" section base.
	@param TextSectionSize - Caller-allocated variable to store the ".text" section size.
	@return Status of the section search.
*/
NTSTATUS
Utilities::FindModuleTextSection (
	_In_ PVOID ImageBase,
	_Inout_ PVOID* TextSectionBase,
	_Inout_ SIZE_T* TextSectionSize
	)
{
	NTSTATUS status;
	PIMAGE_DOS_HEADER driverDosHeader;
	PIMAGE_NT_HEADERS_C driverNtHeader;
	PIMAGE_SECTION_HEADER driverSectionHeader;
	ULONG i;

	status = STATUS_SUCCESS;
	*TextSectionBase = NULL;
	*TextSectionSize = 0;

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
		if (_stricmp(reinterpret_cast<const char*>(&driverSectionHeader[i].Name), ".text") == 0)
		{
			*TextSectionBase = RCAST<PVOID>(RCAST<ULONG_PTR>(driverDosHeader) + driverSectionHeader[i].VirtualAddress);
			*TextSectionSize = driverSectionHeader[i].SizeOfRawData;
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