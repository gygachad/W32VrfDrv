#pragma once

#include "..\common.h"

PMEMORY_LOG_LIST	g_pMemoryLogList = NULL;

PRTL_HEAP_IMPORT_TABLE_HOOK
HookRtlHeapFunctions(
	_In_ char* cImporterDriverName,
	_In_ PMEMORY_LOG_LIST pMemoryLogList
)
{
	PRTL_HEAP_IMPORT_TABLE_HOOK	pHeapHook = NULL;

	pHeapHook = ExAllocatePoolWithTag(NonPagedPool, sizeof(RTL_HEAP_IMPORT_TABLE_HOOK), IMPORT_HOOK_TAG);

	if (!pHeapHook)
		return NULL;

	pHeapHook->pRtlAllocateHeapHook	= HookImportTableEntry(cImporterDriverName, "ntoskrnl.exe", "RtlAllocateHeap", (PVOID)RtlAllocateHeap_Hook);
	pHeapHook->pRtlFreeHeapHook		= HookImportTableEntry(cImporterDriverName, "ntoskrnl.exe", "RtlFreeHeap", (PVOID)RtlFreeHeap_Hook);
	
	g_pMemoryLogList = pMemoryLogList;

	if (!pHeapHook->pRtlAllocateHeapHook	||
		!pHeapHook->pRtlFreeHeapHook		||
		!g_pMemoryLogList)
	{
		UnhookRtlHeapFunctions(pHeapHook);

		return NULL;
	}

	return pHeapHook;
}

NTSTATUS
UnhookRtlHeapFunctions(
	_In_ PRTL_HEAP_IMPORT_TABLE_HOOK	pHeapHook
)
{
	if (pHeapHook)
	{
		if(pHeapHook->pRtlAllocateHeapHook)
			UnhookImportTableEntry(pHeapHook->pRtlAllocateHeapHook);
		if (pHeapHook->pRtlFreeHeapHook)
			UnhookImportTableEntry(pHeapHook->pRtlFreeHeapHook);

		ExFreePoolWithTag(pHeapHook, IMPORT_HOOK_TAG);
	}

	return STATUS_SUCCESS;
}

NTSTATUS
FillRtlAllocateHeapLogRecord(
	_In_	PEPROCESS	pEprocess,
	_In_	PVOID		HeapHandle,
	_In_	ULONG		Flags,
	_In_	SIZE_T		Size,
	_In_	PVOID		pAddr,
	_In_	PVOID		pStack,
	_Out_	PRTL_ALLOCATE_HEAP_LOG_RECORD	pRtlAllocateHeapLogRecord
)
{
	SIZE_T	StackSize;

	if (!pEprocess || !pRtlAllocateHeapLogRecord)
		return STATUS_INVALID_PARAMETER;

	RtlZeroBytes(pRtlAllocateHeapLogRecord, sizeof(RTL_ALLOCATE_HEAP_LOG_RECORD));

	pRtlAllocateHeapLogRecord->FType	= RtlAllocateHeap_Type;
	pRtlAllocateHeapLogRecord->cbSize	= sizeof(RTL_ALLOCATE_HEAP_LOG_RECORD) - MAXIMUM_STACK_SIZE;

	pRtlAllocateHeapLogRecord->HeapHandle	= HeapHandle;
	pRtlAllocateHeapLogRecord->Flags		= Flags;
	pRtlAllocateHeapLogRecord->Size			= Size;
	pRtlAllocateHeapLogRecord->pAddr		= pAddr;

	StackSize = GetStackSizeForLog(pEprocess, pStack);

	if (StackSize)
	{
		RtlCopyBytes(pRtlAllocateHeapLogRecord->pStack, pStack, StackSize);

		pRtlAllocateHeapLogRecord->cbSize += StackSize;
	}

	return STATUS_SUCCESS;
}

NTSTATUS
FillRtlFreeHeapLogRecord(
	_In_	PEPROCESS	pEprocess,
	_In_	PVOID		HeapHandle,
	_In_	ULONG		Flags,
	_In_	PVOID		pAddr,
	_In_	PVOID		pStack,
	_Out_	PRTL_FREE_HEAP_LOG_RECORD	pRtlFreeHeapLogRecord
)
{
	SIZE_T	StackSize;

	if (!pEprocess || !pRtlFreeHeapLogRecord)
		return STATUS_INVALID_PARAMETER;

	RtlZeroBytes(pRtlFreeHeapLogRecord, sizeof(RTL_FREE_HEAP_LOG_RECORD));

	pRtlFreeHeapLogRecord->FType	= RtlFreeHeap_Type;
	pRtlFreeHeapLogRecord->cbSize	= sizeof(RTL_FREE_HEAP_LOG_RECORD) - MAXIMUM_STACK_SIZE;

	pRtlFreeHeapLogRecord->HeapHandle	= HeapHandle;
	pRtlFreeHeapLogRecord->Flags		= Flags;
	pRtlFreeHeapLogRecord->pAddr		= pAddr;

	StackSize = GetStackSizeForLog(pEprocess, pStack);

	if (StackSize)
	{
		RtlCopyBytes(pRtlFreeHeapLogRecord->pStack, pStack, StackSize);

		pRtlFreeHeapLogRecord->cbSize += StackSize;
	}

	return STATUS_SUCCESS;
}

SIZE_T
GetStackSizeForLog(
	_In_	PEPROCESS	pEprocess,
	_In_	PVOID	pStack
)
{
	SIZE_T StackSize;
	SIZE_T MaximumStackSize;

	if (!pStack || !pEprocess)
		return 0x0;

	StackSize = 0x0;
	MaximumStackSize = MAXIMUM_STACK_SIZE;

	while(MaximumStackSize)
	{
		if (!MmIsAddressValid(pStack))
			return StackSize;

		//Размер от стартового адреса, до начала новой страницы
		StackSize += (PBYTE)PAGE_ALIGN(pStack) + PAGE_SIZE - (PBYTE)(pStack);

		//Этого достаточно
		if (StackSize >= MAXIMUM_STACK_SIZE)
		{
			StackSize = MAXIMUM_STACK_SIZE;
			return StackSize;
		}

		MaximumStackSize -= StackSize;

		pStack = (PBYTE)pStack + StackSize;
	}

	return StackSize;
}

PVOID
RtlAllocateHeap_Hook(
	_In_ PVOID  HeapHandle,
	_In_ ULONG  Flags,
	_In_ SIZE_T  Size
)
{
	PPROCESS_MEMORY_LOG	pProcessMemoryLog;
	PVOID			pAddr;
	PEPROCESS		pEprocess;

	pAddr = NULL;

	pEprocess = PsGetCurrentProcess();

	if (g_pMemoryLogList)
	{
		ExAcquireFastMutex(&g_pMemoryLogList->kMutex);

		pProcessMemoryLog = GetMemoryLogByEProcess(g_pMemoryLogList, pEprocess);

		if (pProcessMemoryLog)
		{
			//CHUNK_START_COOKIE
			//SIZE
			//HeapMemory
			//CHUNK_END_COOKIE

			BYTE pStartCookie[] = HEAP_START_TAG;
			BYTE pEndCookie[] = HEAP_END_TAG;

			HEAP_START_COOKIE	sStartCookie;
			HEAP_END_COOKIE		sEndCookie;

			memcpy(sStartCookie.pStartCookie, pStartCookie, sizeof(sStartCookie.pStartCookie));
			sStartCookie.ulSize = Size;

			memcpy(sEndCookie.pEndCookie, pEndCookie, sizeof(sEndCookie.pEndCookie));

			pAddr = RtlAllocateHeap(HeapHandle, Flags, Size + sizeof(HEAP_START_COOKIE) + sizeof(HEAP_END_COOKIE));

			*((PHEAP_START_COOKIE)pAddr) = sStartCookie;
			*((PHEAP_END_COOKIE)((PBYTE)pAddr + Size + sizeof(HEAP_START_COOKIE))) = sEndCookie;

			pAddr = (PBYTE)pAddr + sizeof(HEAP_START_COOKIE);

			RTL_ALLOCATE_HEAP_LOG_RECORD RtlAllocateHeapLogRec = { 0x0 };

			PVOID	pStack = _AddressOfReturnAddress();

			FillRtlAllocateHeapLogRecord(pEprocess, HeapHandle, Flags, Size, pAddr, pStack, &RtlAllocateHeapLogRec);

			AddToMemoryLog(pProcessMemoryLog, (PBYTE)&RtlAllocateHeapLogRec, RtlAllocateHeapLogRec.cbSize);
		}

		ExReleaseFastMutex(&g_pMemoryLogList->kMutex);
	}

	if(pAddr == NULL)
		pAddr = RtlAllocateHeap(HeapHandle, Flags, Size);

	return pAddr;
}

LOGICAL
RtlFreeHeap_Hook(
	_In_ PVOID  HeapHandle,
	_In_ ULONG  Flags,
	_In_ PVOID  HeapBase
)
{

	PPROCESS_MEMORY_LOG	pProcessMemoryLog;
	PVOID			pAddr;
	PEPROCESS		pEprocess;
	LOGICAL			bResult;

	bResult = FALSE;
	pAddr = HeapBase;

	pEprocess = PsGetCurrentProcess();

	if (g_pMemoryLogList)
	{
		ExAcquireFastMutex(&g_pMemoryLogList->kMutex);
		pProcessMemoryLog = GetMemoryLogByEProcess(g_pMemoryLogList, pEprocess);

		if (pProcessMemoryLog)
		{
			RTL_FREE_HEAP_LOG_RECORD RtlFreeHeapLogRec = { 0x0 };
			PVOID	pStack = _AddressOfReturnAddress();

			FillRtlFreeHeapLogRecord(pEprocess, HeapHandle, Flags, pAddr, pStack, &RtlFreeHeapLogRec);

			AddToMemoryLog(pProcessMemoryLog, (PBYTE)&RtlFreeHeapLogRec, RtlFreeHeapLogRec.cbSize);
		}
		ExReleaseFastMutex(&g_pMemoryLogList->kMutex);

		BYTE pStartCookie[]		= HEAP_START_TAG;
		BYTE pEndCookie[]		= HEAP_END_TAG;
		
		PHEAP_START_COOKIE pHeapStartCookie = (PHEAP_START_COOKIE)((PBYTE)pAddr - sizeof(HEAP_START_COOKIE));

		if (*(PULONG64)(pHeapStartCookie->pStartCookie) == *(PULONG64)pStartCookie)
		{
			SIZE_T	Size = pHeapStartCookie->ulSize;

			PHEAP_END_COOKIE pHeapEndCookie = (PHEAP_END_COOKIE)((PBYTE)pAddr + Size);

			if (*(PULONG64)(pHeapEndCookie->pEndCookie) != *(PULONG64)pEndCookie)
				KeBugCheckEx(BAD_POOL_CALLER, (ULONG_PTR)pAddr, (ULONG_PTR)Size, (ULONG_PTR)pHeapStartCookie, (ULONG_PTR)pHeapEndCookie);

			pAddr = (PBYTE)pAddr - sizeof(HEAP_START_COOKIE);

			RtlFillMemory(pAddr, Size + sizeof(HEAP_START_COOKIE) + sizeof(HEAP_END_COOKIE), 0xcc);
		}
	}

	return
		RtlFreeHeap(HeapHandle, Flags, pAddr);
}
