/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 *
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include <fltKernel.h>
#include <dontuse.h>
#include <ntstrsafe.h>

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int UINT;

typedef enum _PS_CREATE_STATE
{
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName,
	PsCreateSuccess,
	PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO
{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		struct
		{
			union
			{
				ULONG InitFlags;
				struct
				{
					UCHAR WriteOutputOnExit : 1;
					UCHAR DetectManifest : 1;
					UCHAR IFEOSkipDebugger : 1;
					UCHAR IFEODoNotPropagateKeyState : 1;
					UCHAR SpareBits1 : 4;
					UCHAR SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				} Dummy;
			};
			ACCESS_MASK AdditionalFileAccess;
		} InitState;

		struct
		{
			HANDLE FileHandle;
		} FailSection;

		struct
		{
			USHORT DllCharacteristics;
		} ExeFormat;

		struct
		{
			HANDLE IFEOKey;
		} ExeName;

		struct
		{
			union
			{
				ULONG OutputFlags;
				struct
				{
					UCHAR ProtectedProcess : 1;
					UCHAR AddressSpaceOverride : 1;
					UCHAR DevOverrideEnabled : 1;
					UCHAR ManifestDetected : 1;
					UCHAR ProtectedProcessLight : 1;
					UCHAR SpareBits1 : 3;
					UCHAR SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				} Dummy;
			};
			HANDLE FileHandle;
			HANDLE SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG UserProcessParametersWow64;
			ULONG CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, * PPS_CREATE_INFO;

typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union
	{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	WORD Flags;
	WORD Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	PVOID Handle;
} CURDIR, * PCURDIR;

#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG_PTR EnvironmentSize;
	ULONG_PTR EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;

	UNICODE_STRING RedirectionDllName; // REDSTONE4
	UNICODE_STRING HeapPartitionName; // 19H1
	ULONG_PTR DefaultThreadpoolCpuSetMasks;
	ULONG DefaultThreadpoolCpuSetMaskCount;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PVOID						  Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PVOID						  PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;

#define STARTF_USESHOWWINDOW       0x00000001
#define STARTF_USESTDHANDLES       0x00000100

#define SW_HIDE             0

#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000
#define PS_ATTRIBUTE_INPUT 0x00020000
#define PS_ATTRIBUTE_UNKNOWN 0x00040000

#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT 0x00000002
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008
#define PROCESS_CREATE_FLAGS_LARGE_PAGES 0x00000010

#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED              0x01

#define PsAttributeValue(Number, Thread, Input, Unknown) \
	(((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Unknown) ? PS_ATTRIBUTE_UNKNOWN : 0))

typedef enum _PS_ATTRIBUTE_NUM
{
	PsAttributeParentProcess, // in HANDLE
	PsAttributeDebugPort, // in HANDLE
	PsAttributeToken, // in HANDLE
	PsAttributeClientId, // out PCLIENT_ID
	PsAttributeTebAddress, // out PTEB *
	PsAttributeImageName, // in PWSTR
	PsAttributeImageInfo, // out PSECTION_IMAGE_INFORMATION
	PsAttributeMemoryReserve, // in PPS_MEMORY_RESERVE
	PsAttributePriorityClass, // in UCHAR
	PsAttributeErrorMode, // in ULONG
	PsAttributeStdHandleInfo, // 10, in PPS_STD_HANDLE_INFO
	PsAttributeHandleList, // in PHANDLE
	PsAttributeGroupAffinity, // in PGROUP_AFFINITY
	PsAttributePreferredNode, // in PUSHORT
	PsAttributeIdealProcessor, // in PPROCESSOR_NUMBER
	PsAttributeUmsThread, // ? in PUMS_CREATE_THREAD_ATTRIBUTES
	PsAttributeMitigationOptions, // in UCHAR
	PsAttributeProtectionLevel, // in ULONG
	PsAttributeSecureProcess, // since THRESHOLD
	PsAttributeJobList,
	PsAttributeChildProcessPolicy, // since THRESHOLD2
	PsAttributeAllApplicationPackagesPolicy, // since REDSTONE
	PsAttributeWin32kFilter,
	PsAttributeSafeOpenPromptOriginClaim,
	PsAttributeBnoIsolation, // PS_BNO_ISOLATION_PARAMETERS
	PsAttributeDesktopAppPolicy, // in ULONG
	PsAttributeChpe, // since REDSTONE3
	PsAttributeMax
} PS_ATTRIBUTE_NUM;

EXTERN_C_START
NTKERNELAPI NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
NTKERNELAPI PVOID ObQueryNameInfo(_In_ PVOID Object);
NTKERNELAPI NTSTATUS ObCreateObject(__in KPROCESSOR_MODE ProbeMode, __in POBJECT_TYPE ObjectType, __in POBJECT_ATTRIBUTES ObjectAttributes, __in KPROCESSOR_MODE OwnershipMode, __inout_opt PVOID ParseContext, __in ULONG ObjectBodySize, __in ULONG PagedPoolCharge, __in ULONG NonPagedPoolCharge, __out PVOID* Object);
__declspec(dllimport) POBJECT_TYPE* IoDriverObjectType;
__declspec(dllimport) POBJECT_TYPE* IoDeviceObjectType;
NTKERNELAPI VOID IoDeleteDriver(IN PDRIVER_OBJECT DriverObject);
//
// This function is actually exported! For some reason Microsoft exported it by ordinal.
// Thanks Alex Ionescu for this find.
//
//NTSYSCALLAPI NTSTATUS NTAPI ZwCreateUserProcess(_Out_ PHANDLE ProcessHandle, _Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK ProcessDesiredAccess, _In_ ACCESS_MASK ThreadDesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes, _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes, _In_ ULONG ProcessFlags, _In_ ULONG ThreadFlags, _In_opt_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters, _Inout_ PPS_CREATE_INFO CreateInfo, _In_opt_ PPS_ATTRIBUTE_LIST AttributeList );
typedef NTSTATUS(NTAPI* ZwCreateUserProcess_t)(_Out_ PHANDLE ProcessHandle, _Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK ProcessDesiredAccess, _In_ ACCESS_MASK ThreadDesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes, _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes, _In_ ULONG ProcessFlags, _In_ ULONG ThreadFlags, _In_opt_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters, _Inout_ PPS_CREATE_INFO CreateInfo, _In_opt_ PPS_ATTRIBUTE_LIST AttributeList);;
//NTSYSAPI NTSTATUS NTAPI ZwCreateNamedPipeFile(OUT PHANDLE NamedPipeFileHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG ShareAccess, IN ULONG CreateDisposition, IN ULONG CreateOptions, IN BOOLEAN  WriteModeMessage, IN BOOLEAN  ReadModeMessage, IN BOOLEAN  NonBlocking, IN ULONG MaxInstances, IN ULONG InBufferSize, IN ULONG OutBufferSize, IN PLARGE_INTEGER DefaultTimeOut);
NTKERNELAPI NTSTATUS PsResumeProcess(IN PEPROCESS Process);
NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);
NTKERNELAPI PVOID RtlFindExportedRoutineByName(_In_ PVOID BaseAddress, _In_ CONST CHAR* ExportName);
NTKERNELAPI NTSTATUS ZwQueryInformationProcess(_In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PVOID ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength);
NTKERNELAPI POBJECT_TYPE NTAPI ObGetObjectType(_In_ PVOID Object);
EXTERN_C_END

typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_DIRECTORY_ENTRY
{
	_OBJECT_DIRECTORY_ENTRY* ChainLink;
	PVOID Object;
	ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, * POBJECT_DIRECTORY_ENTRY;

typedef struct _DEVICE_MAP* PDEVICE_MAP;

typedef struct _OBJECT_DIRECTORY
{
	POBJECT_DIRECTORY_ENTRY HashBuckets[37];
	EX_PUSH_LOCK Lock;
	PDEVICE_MAP DeviceMap;
	ULONG SessionId;
	PVOID NamespaceEntry;
	ULONG Flags;
} OBJECT_DIRECTORY, * POBJECT_DIRECTORY;

typedef struct _OBJECT_HEADER_NAME_INFO {
	POBJECT_DIRECTORY        Directory;
	UNICODE_STRING                Name;
	ULONG                                ReferenceCount;
}OBJECT_HEADER_NAME_INFO, * POBJECT_HEADER_NAME_INFO;

typedef struct _IMAGE_DOS_HEADER
{
	WORD e_magic;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	LONG e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD  Machine;
	WORD  NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	WORD  SizeOfOptionalHeader;
	WORD  Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG VirtualAddress;
	ULONG Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
	BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	WORD  NumberOfRelocations;
	WORD  NumberOfLinenumbers;
	ULONG Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;


#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD                 Magic;
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	ULONG                SizeOfCode;
	ULONG                SizeOfInitializedData;
	ULONG                SizeOfUninitializedData;
	ULONG                AddressOfEntryPoint;
	ULONG                BaseOfCode;
	ULONGLONG            ImageBase;
	ULONG                SectionAlignment;
	ULONG                FileAlignment;
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
	WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	ULONG                Win32VersionValue;
	ULONG                SizeOfImage;
	ULONG                SizeOfHeaders;
	ULONG                CheckSum;
	WORD                 Subsystem;
	WORD                 DllCharacteristics;
	ULONGLONG            SizeOfStackReserve;
	ULONGLONG            SizeOfStackCommit;
	ULONGLONG            SizeOfHeapReserve;
	ULONGLONG            SizeOfHeapCommit;
	ULONG                LoaderFlags;
	ULONG                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

#undef PIMAGE_NT_HEADERS
typedef struct _IMAGE_NT_HEADERS {
	ULONG                 Signature;
	IMAGE_FILE_HEADER     FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS_C, * PIMAGE_NT_HEADERS_C;

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x4550

#define IMAGE_FIRST_SECTION(h) ((PIMAGE_SECTION_HEADER)((ULONG64)h+FIELD_OFFSET(IMAGE_NT_HEADERS_C,OptionalHeader)+((PIMAGE_NT_HEADERS_C)(h))->FileHeader.SizeOfOptionalHeader))

//
// Following AFD IOCTLs stolen from ReactOS.
//
/* IOCTL Generation */
#define FSCTL_AFD_BASE                  FILE_DEVICE_NETWORK
#define _AFD_CONTROL_CODE(Operation,Method) \
  ((FSCTL_AFD_BASE)<<12 | (Operation<<2) | Method)

/* AFD Commands */
#define AFD_BIND			0
#define AFD_CONNECT			1
#define AFD_START_LISTEN		2
#define AFD_WAIT_FOR_LISTEN		3
#define AFD_ACCEPT			4
#define AFD_RECV			5
#define AFD_RECV_DATAGRAM		6
#define AFD_SEND			7
#define AFD_SEND_DATAGRAM		8
#define AFD_SELECT			9
#define AFD_DISCONNECT			10
#define AFD_GET_SOCK_NAME		11
#define AFD_GET_PEER_NAME               12
#define AFD_GET_TDI_HANDLES		13
#define AFD_SET_INFO			14
#define AFD_GET_CONTEXT_SIZE		15
#define AFD_GET_CONTEXT			16
#define AFD_SET_CONTEXT			17
#define AFD_SET_CONNECT_DATA		18
#define AFD_SET_CONNECT_OPTIONS		19
#define AFD_SET_DISCONNECT_DATA		20
#define AFD_SET_DISCONNECT_OPTIONS	21
#define AFD_GET_CONNECT_DATA		22
#define AFD_GET_CONNECT_OPTIONS		23
#define AFD_GET_DISCONNECT_DATA		24
#define AFD_GET_DISCONNECT_OPTIONS	25
#define AFD_SET_CONNECT_DATA_SIZE       26
#define AFD_SET_CONNECT_OPTIONS_SIZE    27
#define AFD_SET_DISCONNECT_DATA_SIZE    28
#define AFD_SET_DISCONNECT_OPTIONS_SIZE 29
#define AFD_GET_INFO			30
#define AFD_EVENT_SELECT		33
#define AFD_ENUM_NETWORK_EVENTS         34
#define AFD_DEFER_ACCEPT		35
#define AFD_GET_PENDING_CONNECT_DATA	41
#define AFD_VALIDATE_GROUP		42

/* AFD IOCTLs */

#define IOCTL_AFD_BIND \
  _AFD_CONTROL_CODE(AFD_BIND, METHOD_NEITHER)
#define IOCTL_AFD_CONNECT \
  _AFD_CONTROL_CODE(AFD_CONNECT, METHOD_NEITHER)
#define IOCTL_AFD_START_LISTEN \
  _AFD_CONTROL_CODE(AFD_START_LISTEN, METHOD_NEITHER)
#define IOCTL_AFD_WAIT_FOR_LISTEN \
  _AFD_CONTROL_CODE(AFD_WAIT_FOR_LISTEN, METHOD_BUFFERED )
#define IOCTL_AFD_ACCEPT \
  _AFD_CONTROL_CODE(AFD_ACCEPT, METHOD_BUFFERED )
#define IOCTL_AFD_RECV \
  _AFD_CONTROL_CODE(AFD_RECV, METHOD_NEITHER)
#define IOCTL_AFD_RECV_DATAGRAM \
  _AFD_CONTROL_CODE(AFD_RECV_DATAGRAM, METHOD_NEITHER)
#define IOCTL_AFD_SEND \
  _AFD_CONTROL_CODE(AFD_SEND, METHOD_NEITHER)
#define IOCTL_AFD_SEND_DATAGRAM \
  _AFD_CONTROL_CODE(AFD_SEND_DATAGRAM, METHOD_NEITHER)
#define IOCTL_AFD_SELECT \
  _AFD_CONTROL_CODE(AFD_SELECT, METHOD_BUFFERED )
#define IOCTL_AFD_DISCONNECT \
  _AFD_CONTROL_CODE(AFD_DISCONNECT, METHOD_NEITHER)
#define IOCTL_AFD_GET_SOCK_NAME \
  _AFD_CONTROL_CODE(AFD_GET_SOCK_NAME, METHOD_NEITHER)
#define IOCTL_AFD_GET_PEER_NAME \
  _AFD_CONTROL_CODE(AFD_GET_PEER_NAME, METHOD_NEITHER)
#define IOCTL_AFD_GET_TDI_HANDLES \
  _AFD_CONTROL_CODE(AFD_GET_TDI_HANDLES, METHOD_NEITHER)
#define IOCTL_AFD_SET_INFO \
  _AFD_CONTROL_CODE(AFD_SET_INFO, METHOD_NEITHER)
#define IOCTL_AFD_GET_CONTEXT_SIZE \
  _AFD_CONTROL_CODE(AFD_GET_CONTEXT_SIZE, METHOD_NEITHER)
#define IOCTL_AFD_GET_CONTEXT \
  _AFD_CONTROL_CODE(AFD_GET_CONTEXT, METHOD_NEITHER)
#define IOCTL_AFD_SET_CONTEXT \
  _AFD_CONTROL_CODE(AFD_SET_CONTEXT, METHOD_NEITHER)
#define IOCTL_AFD_SET_CONNECT_DATA \
  _AFD_CONTROL_CODE(AFD_SET_CONNECT_DATA, METHOD_NEITHER)
#define IOCTL_AFD_SET_CONNECT_OPTIONS \
  _AFD_CONTROL_CODE(AFD_SET_CONNECT_OPTIONS, METHOD_NEITHER)
#define IOCTL_AFD_SET_DISCONNECT_DATA \
  _AFD_CONTROL_CODE(AFD_SET_DISCONNECT_DATA, METHOD_NEITHER)
#define IOCTL_AFD_SET_DISCONNECT_OPTIONS \
  _AFD_CONTROL_CODE(AFD_SET_DISCONNECT_OPTIONS, METHOD_NEITHER)
#define IOCTL_AFD_GET_CONNECT_DATA \
  _AFD_CONTROL_CODE(AFD_GET_CONNECT_DATA, METHOD_NEITHER)
#define IOCTL_AFD_GET_CONNECT_OPTIONS \
  _AFD_CONTROL_CODE(AFD_GET_CONNECT_OPTIONS, METHOD_NEITHER)
#define IOCTL_AFD_GET_DISCONNECT_DATA \
  _AFD_CONTROL_CODE(AFD_GET_DISCONNECT_DATA, METHOD_NEITHER)
#define IOCTL_AFD_GET_DISCONNECT_OPTIONS \
  _AFD_CONTROL_CODE(AFD_GET_DISCONNECT_OPTIONS, METHOD_NEITHER)
#define IOCTL_AFD_SET_CONNECT_DATA_SIZE \
  _AFD_CONTROL_CODE(AFD_SET_CONNECT_DATA_SIZE, METHOD_NEITHER)
#define IOCTL_AFD_SET_CONNECT_OPTIONS_SIZE \
  _AFD_CONTROL_CODE(AFD_SET_CONNECT_OPTIONS_SIZE, METHOD_NEITHER)
#define IOCTL_AFD_SET_DISCONNECT_DATA_SIZE \
  _AFD_CONTROL_CODE(AFD_SET_DISCONNECT_DATA_SIZE, METHOD_NEITHER)
#define IOCTL_AFD_SET_DISCONNECT_OPTIONS_SIZE \
  _AFD_CONTROL_CODE(AFD_SET_DISCONNECT_OPTIONS_SIZE, METHOD_NEITHER)
#define IOCTL_AFD_GET_INFO \
  _AFD_CONTROL_CODE(AFD_GET_INFO, METHOD_NEITHER)
#define IOCTL_AFD_EVENT_SELECT \
  _AFD_CONTROL_CODE(AFD_EVENT_SELECT, METHOD_NEITHER)
#define IOCTL_AFD_DEFER_ACCEPT \
  _AFD_CONTROL_CODE(AFD_DEFER_ACCEPT, METHOD_NEITHER)
#define IOCTL_AFD_GET_PENDING_CONNECT_DATA \
  _AFD_CONTROL_CODE(AFD_GET_PENDING_CONNECT_DATA, METHOD_NEITHER)
#define IOCTL_AFD_ENUM_NETWORK_EVENTS \
  _AFD_CONTROL_CODE(AFD_ENUM_NETWORK_EVENTS, METHOD_NEITHER)
#define IOCTL_AFD_VALIDATE_GROUP \
  _AFD_CONTROL_CODE(AFD_VALIDATE_GROUP, METHOD_NEITHER)

#define IMAGE_SCN_MEM_EXECUTE 0x20000000

typedef struct _EXTENDED_DRIVER_EXTENSION
{
	struct _DRIVER_OBJECT* DriverObject;
	PDRIVER_ADD_DEVICE AddDevice;
	ULONG Count;
	UNICODE_STRING ServiceKeyName;
	PVOID ClientDriverExtension;
	PFS_FILTER_CALLBACKS FsFilterCallbacks;
} EXTENDED_DRIVER_EXTENSION, * PEXTENDED_DRIVER_EXTENSION;

//
// Extended Device Object Extension Structure
//
typedef struct _EXTENDED_DEVOBJ_EXTENSION
{
	CSHORT Type;
	USHORT Size;
	PDEVICE_OBJECT DeviceObject;
	ULONG PowerFlags;
	struct _DEVICE_OBJECT_POWER_EXTENSION* Dope;
	ULONG ExtensionFlags;
	struct _DEVICE_NODE* DeviceNode;
	PDEVICE_OBJECT AttachedTo;
	LONG StartIoCount;
	LONG StartIoKey;
	ULONG StartIoFlags;
	struct _VPB* Vpb;
} EXTENDED_DEVOBJ_EXTENSION, * PEXTENDED_DEVOBJ_EXTENSION;

// This structure is not correct on Windows 7, but the offsets we need are still correct.
typedef struct _OBJECT_HEADER
{
	LONG PointerCount;
	union
	{
		LONG HandleCount;
		PVOID NextToFree;
	};
	EX_PUSH_LOCK Lock;
	UCHAR TypeIndex;
	union
	{
		UCHAR TraceFlags;
		struct
		{
			UCHAR DbgRefTrace : 1;
			UCHAR DbgTracePermanent : 1;
			UCHAR Reserved : 6;
		} bar;
	};
	UCHAR InfoMask;
	union
	{
		UCHAR Flags;
		struct
		{
			UCHAR NewObject : 1;
			UCHAR KernelObject : 1;
			UCHAR KernelOnlyAccess : 1;
			UCHAR ExclusiveObject : 1;
			UCHAR PermanentObject : 1;
			UCHAR DefaultSecurityQuota : 1;
			UCHAR SingleHandleEntry : 1;
			UCHAR DeletedInline : 1;
		} foo;
	};
	union
	{
		PVOID ObjectCreateInfo;
		PVOID QuotaBlockCharged;
	};
	PVOID SecurityDescriptor;
	QUAD Body;
} OBJECT_HEADER, * POBJECT_HEADER;

#if (defined _M_X64) || (defined _M_ARM64)
C_ASSERT(FIELD_OFFSET(OBJECT_HEADER, Body) == 0x030);
C_ASSERT(sizeof(OBJECT_HEADER) == 0x038);
#else
C_ASSERT(FIELD_OFFSET(OBJECT_HEADER, Body) == 0x018);
C_ASSERT(sizeof(OBJECT_HEADER) == 0x020);
#endif

#define OBJECT_TO_OBJECT_HEADER(Object) CONTAINING_RECORD((Object), OBJECT_HEADER, Body)
#define GET_OB_HEADER_COOKIE(Object) OBJECT_TO_OBJECT_HEADER(Object)->TypeIndex ^ (RCAST<ULONG64>(OBJECT_TO_OBJECT_HEADER(Object)) >> 8)

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemPowersInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _PARTIAL_OBJECT_TYPE
{
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;
	PVOID DefaultObject;
	ULONG Index;
} PARTIAL_OBJECT_TYPE, *PPARTIAL_OBJECT_TYPE;

#define MAX_OBJECT_TYPE_INDEX 64  // As of Windows 10 there are 64 object types.
#define FAST_IO_DISPATCH_COUNT 26

typedef struct _AFD_WSABUF {
	UINT  len;
	PCHAR buf;
} AFD_WSABUF, * PAFD_WSABUF;

typedef struct  _AFD_RECV_INFO {
	PAFD_WSABUF			BufferArray;
	ULONG				BufferCount;
	ULONG				AfdFlags;
	ULONG				TdiFlags;
} AFD_RECV_INFO, * PAFD_RECV_INFO;

typedef struct  _AFD_SEND_INFO {
	PAFD_WSABUF			BufferArray;
	ULONG				BufferCount;
	ULONG				AfdFlags;
	ULONG				TdiFlags;
} AFD_SEND_INFO, * PAFD_SEND_INFO;

/* AFD SEND/RECV Flags */
#define AFD_SKIP_FIO			0x1L
#define AFD_OVERLAPPED			0x2L
#define AFD_IMMEDIATE                   0x4L

#define INFINITE            0xFFFFFFFF  // Infinite timeout

typedef struct _SECURITY_ATTRIBUTES {
	DWORD nLength;
	PVOID lpSecurityDescriptor;
	BOOLEAN bInheritHandle;
} SECURITY_ATTRIBUTES, * PSECURITY_ATTRIBUTES, * LPSECURITY_ATTRIBUTES;

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;     // RVA from base of image
	DWORD   AddressOfNames;         // RVA from base of image
	DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_NT_HEADERS64 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;