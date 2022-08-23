#pragma once

#define DEFAULY_W32_PROCESS "explorer.exe"

#define RTL_HEAP_VERIFIER_TAG 'TRVH'

typedef struct _BINARY_NAME_ENTRY
{
	//Список
	LIST_ENTRY		ListEntry;

	//Имя процесса
	UNICODE_STRING	ProcessName;

}BINARY_NAME_ENTRY, *PBINARY_NAME_ENTRY;

typedef struct _RTLHEAP_VERIFIER
{
	//Блокировка
	FAST_MUTEX			kMutex;

	//Список SBINARY_NAME_ENTRY структур
	LIST_ENTRY			pBinaryNameList;

	//Логи для процессов
	PMEMORY_LOG_LIST	pMemoryLogList;

	//RtlHeap hook
	PRTL_HEAP_IMPORT_TABLE_HOOK	pWin32kImportTableHeapHook;
	PRTL_HEAP_IMPORT_TABLE_HOOK	pWin32kBaseImportTableHeapHook;
	PRTL_HEAP_IMPORT_TABLE_HOOK	pWin32kFullImportTableHeapHook;

	BOOLEAN				bInited;
}RTLHEAP_VERIFIER, *PRTLHEAP_VERIFIER;

PRTLHEAP_VERIFIER
CreateRtlHeapVerifier();

VOID
FreeRtlHeapVerifier(
	_In_ PRTLHEAP_VERIFIER pHeapVerifier
);

VOID
FreeBinaryNamesList(
	_In_ PRTLHEAP_VERIFIER	pHeapVerifier
);

BOOL
IsProcessNameInBinaryList(
	_In_ PRTLHEAP_VERIFIER	pHeapVerifier,
	_In_ PUNICODE_STRING pCreatedProcessName
);

NTSTATUS
AddProcessBinaryName(
	_In_ PRTLHEAP_VERIFIER	pHeapVerifier,
	_In_ wchar_t* pCreatedProcessName,
	_In_ ULONG ulProcessNameLen
);

NTSTATUS
RemoveProcessBinaryName(
	_In_ PRTLHEAP_VERIFIER	pHeapVerifier,
	_In_ wchar_t* pCreatedProcessName,
	_In_ ULONG ulProcessNameLen
);

VOID
RtlHVCreateProcessRoutine(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);