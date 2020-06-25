/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "ProcessQueue.h"
#include "NtFunctionResolver.h"

typedef class Utilities
{
public:
	//
	// Queue used for starting processes.
	//
	static PPROCESS_QUEUE ProcessQueue;

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
		_In_ PVOID DriverBase,
		_In_ PVOID ThreadFunction
		);

	static CONST RTL_PROCESS_MODULE_INFORMATION GetDriverModule (
		_In_ CONST CHAR* ModuleName
		);

	static NTSTATUS CreatePipe (
		_Inout_ PHANDLE hReadPipe,
		_Inout_ PHANDLE hWritePipe
		);

	static NTSTATUS StartProcess (
		_In_ PUNICODE_STRING CurrentDirectory,
		_In_ PUNICODE_STRING ProcessImageName,
		_In_ PUNICODE_STRING Arguments,
		_In_ CONST LONG Timeout,
		_In_opt_ PHANDLE StdOutHandle
		);

	static NTSTATUS RunCommand (
		_In_ WCHAR* Command,
		_In_ ULONG CommandSize,
		_In_ LONG Timeout,
		_Inout_ BYTE* OutputBuffer,
		_Inout_ ULONG* OutputBufferSize
		);

	static ULONG RVA2Offset (
		_In_ PIMAGE_NT_HEADERS NtHeaders,
		_In_ PIMAGE_SECTION_HEADER SectionHeader,
		_In_ DWORD VirtualAddress
		);

	static PVOID FindExportByName (
		_In_ PVOID Module,
		_In_ CHAR* ExportName,
		_In_ BOOLEAN MappedModule
		);

	static NTSTATUS PeekNamedPipe (
		_In_ HANDLE hNamedPipe,
		_In_ PULONG AvailableReadBytes
		);

} UTILITIES;

#define PROCESS_PARAMETERS_TAG DEFINE_TAG('pPpS')
#define PROCESS_ATTRIBUTES_TAG DEFINE_TAG('aPpS')
#define PROCESS_CMDLINE_TAG DEFINE_TAG('cPpS')
#define PROCESS_OUTPUT_TAG DEFINE_TAG('oPpS')
#define SYSTEM_MODULE_INFO_TAG DEFINE_TAG('mSpS')