/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"

typedef class Utilities
{
public:
	static NTSTATUS FindNextExecSection (
		_In_ PVOID ImageBase,
		_Inout_ PVOID* ExecSectionBase,
		_Inout_ SIZE_T* ExecSectionSize
		);

	static PVOID FindPattern (
		_In_ CONST PVOID Address,
		_In_ CONST SIZE_T Length,
		_In_ CONST CHAR* Pattern,
		_In_ CONST CHAR* Mask
		);

	static BOOLEAN CompareData (
		_In_ CONST CHAR* Data,
		_In_ CONST CHAR* Pattern,
		_In_ CONST CHAR* Mask
		);

	static BOOLEAN CreateHiddenThread (
		_In_ PDRIVER_OBJECT ImpersonateDriver,
		_In_ PVOID ThreadFunction
		);

	static CONST RTL_PROCESS_MODULE_INFORMATION GetDriverModule (
		_In_ CONST CHAR* ModuleName
		);
} UTILITIES;