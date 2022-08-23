#pragma once

#define HEAP_CHUNK_COOKIE_TAG	'GATCPAEH'

#define HEAP_LOGGER_TAG	'HGOL'

#define MAXIMUM_STACK_SIZE 0x1000

#define HEAP_START_TAG { 'H','E','A','P','S','T','A','G' }
#define HEAP_END_TAG { 'H','E','A','P','E','T','A','G' }

typedef enum
{
	RtlAllocateHeap_Type = 0,
	RtlFreeHeap_Type
}FUNCTION_TYPE;

typedef enum
{
	FunctionNotInitialized = 0,
	FunctionStarted,
	FunctionReturned
}FUNCTION_STATE;

typedef struct _HEAP_START_COOKIE
{
	BYTE	pStartCookie[8];
	ULONG64	ulSize;
}HEAP_START_COOKIE, *PHEAP_START_COOKIE;

typedef struct _HEAP_END_COOKIE
{
	BYTE	pEndCookie[8];
}HEAP_END_COOKIE, *PHEAP_END_COOKIE;

typedef	struct _RTL_ALLOCATE_HEAP_LOG_RECORD
{
	FUNCTION_TYPE	FType;
	SIZE_T	cbSize;
	PVOID	HeapHandle;
	ULONG	Flags;
	SIZE_T	Size;
	PVOID	pAddr;
	BYTE	pStack[MAXIMUM_STACK_SIZE];
}RTL_ALLOCATE_HEAP_LOG_RECORD, *PRTL_ALLOCATE_HEAP_LOG_RECORD;

typedef struct _RTL_ALLOCATE_HEAP
{
	FUNCTION_STATE	FState;
	RTL_ALLOCATE_HEAP_LOG_RECORD	RtlAllocHeapLogRec;
}RTL_ALLOCATE_HEAP, *PRTL_ALLOCATE_HEAP;

typedef struct _RTL_FREE_HEAP_LOG_RECORD
{
	FUNCTION_TYPE	FType;
	SIZE_T	cbSize;
	PVOID	HeapHandle;
	ULONG	Flags;
	PVOID	pAddr;
	BYTE	pStack[MAXIMUM_STACK_SIZE];
}RTL_FREE_HEAP_LOG_RECORD, *PRTL_FREE_HEAP_LOG_RECORD;

typedef struct _RTL_FREE_HEAP
{
	FUNCTION_STATE	FState;
	RTL_FREE_HEAP_LOG_RECORD	RtlFreeHeapLogRec;
}RTL_FREE_HEAP, *PRTL_FREE_HEAP;

typedef struct _RTL_HEAP_IMPORT_TABLE_HOOK
{
	PIMPORT_TABLE_HOOK	pRtlAllocateHeapHook;
	PIMPORT_TABLE_HOOK	pRtlFreeHeapHook;
}RTL_HEAP_IMPORT_TABLE_HOOK, *PRTL_HEAP_IMPORT_TABLE_HOOK;

PRTL_HEAP_IMPORT_TABLE_HOOK
HookRtlHeapFunctions(
	_In_ char* cImporterDriverName,
	_In_ PVOID pMemoryLogList
);

NTSTATUS
UnhookRtlHeapFunctions(
	_In_ PRTL_HEAP_IMPORT_TABLE_HOOK	pHeapHook
);

NTSTATUS
FillRtlAllocateHeapLogRecord(
	_In_	PEPROCESS	pEprocess,
	_In_	PVOID		HeapHandle,
	_In_	ULONG		Flags,
	_In_	SIZE_T		Size,
	_In_	PVOID		pAddr,
	_In_	PVOID		pStack,
	_Out_	PRTL_ALLOCATE_HEAP_LOG_RECORD	pRtlAllocateHeapLogRecord
);

NTSTATUS
FillRtlFreeHeapLogRecord(
	_In_	PEPROCESS	pEprocess,
	_In_	PVOID		HeapHandle,
	_In_	ULONG		Flags,
	_In_	PVOID		pAddr,
	_In_	PVOID		pStack,
	_Out_	PRTL_FREE_HEAP_LOG_RECORD	pRtlFreeHeapLogRecord
);

SIZE_T
GetStackSizeForLog(
	_In_	PEPROCESS	pEprocess,
	_In_	PVOID	pStack
);

PVOID
RtlAllocateHeap_Hook(
	_In_ PVOID  HeapHandle,
	_In_ ULONG  Flags,
	_In_ SIZE_T  Size
);

LOGICAL
RtlFreeHeap_Hook(
	_In_ PVOID  HeapHandle,
	_In_ ULONG  Flags,
	_In_ PVOID  HeapBase
);