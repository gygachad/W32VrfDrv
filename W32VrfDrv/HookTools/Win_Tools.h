#pragma once

#define WIN_TOOL_TAG 'TLTW'

#ifdef WIN_7
#include "WIN7_X64.h"
#endif // WIN_7

#ifdef WIN_8
#include "WIN8_X64.h"
#endif // WIN_8

#ifdef WIN_10
#include "WIN10_X64.h"
#endif // WIN_10

#define RVATOVA(_base_, _offset_) ((PUCHAR)(_base_) + (ULONG)(_offset_))

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,             // obsolete...delete
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
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum

} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef 
NTSTATUS(NTAPI * NT_DEVICE_IO_CONTROL_FILE)(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG IoControlCode,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength
	);

typedef
PEPROCESS(NTAPI *pfPsGetProcessWin32Process_t)(
	PEPROCESS pEprocess
	);

typedef
char*(NTAPI* pfPsGetProcessImageFileName_t)(
	PEPROCESS pEprocess
	);

NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
	_In_ PKDEFERRED_ROUTINE Routine,
	_In_opt_ PVOID Context
);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
	_In_ PVOID SystemArgument1
);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
	_In_ PVOID SystemArgument2
);

PVOID
GetSysInf(
	_In_ SYSTEM_INFORMATION_CLASS InfoClass
);

PVOID
GetKernelModuleBase(
	_In_ char *ModuleName
);

//Получить адрес экспортируемой фукции
//ModuleName Имя драйвера, который экспортирует функци
//lpszFunctionName Имя экспортируемой функции
PVOID
KernelGetExportAddress(
	_In_ char *ModuleName,
	_In_ char *lpszFunctionName
);

//Получить адрес импортируемой фукции
//ModuleName Имя драйвера, который импортирует функцию
//ImporterModuleName Имя драйвера, который экспортиурет эту функцию
//lpszFunctionName Имя экспортируемой функции
PVOID
KernelGetImportAddress(
	_In_ char *ModuleName,
	_In_ char *ImporterModuleName,
	_In_ char *lpszFunctionName
);

NTSTATUS
NtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

NTSTATUS
ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

//Получить имя текущего процесса
wchar_t*
GetProcessName(
	_In_ PEPROCESS	pCurProcess
);

//Получить каталог страниц процесса
ULONG64
GetProcessDirectoryTableBase(
	_In_ PEPROCESS	pCurProcess
);

//Задать каталог страниц процесса
VOID
SetProcessDirectoryTableBase(
	_In_ PEPROCESS	pCurProcess,
	_In_ PVOID	NewDirBase
);

NTSTATUS
GetKernelModuleBaseAddress(
	_In_ PCHAR		pModuleName,
	_Out_ PULONG64	pStartAddr,
	_Out_ PULONG64	pEndAddr
);

//Получить физический адрес для конкретного контекста
PHYSICAL_ADDRESS
GetPhysicalAddressForContext(
	_In_ PVOID		pVirtual,
	_In_ ULONG64	pContext
);

//Получить указатель на ret из функции по адресу ее начала
PVOID
GetFunctionRetAddr(
	_In_ PVOID	pFunctionStart
);

PEPROCESS
AttachToFirstGUI(
	_Out_ KAPC_STATE* kState
);

PEPROCESS
AttachToNamedProcess(
	_In_  char* procName,
	_Out_ KAPC_STATE* kState
);

void
DetachFromGUI(
	_In_ PRKAPC_STATE ApcState
);