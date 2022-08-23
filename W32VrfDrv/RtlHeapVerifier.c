#include "common.h"

PRTLHEAP_VERIFIER g_pHeapVerifier = NULL;

PRTLHEAP_VERIFIER
CreateRtlHeapVerifier()
{
	NTSTATUS nStatus;

	PRTLHEAP_VERIFIER pRtlHeapVerifier;

	pRtlHeapVerifier = ExAllocatePoolWithTag(NonPagedPool, sizeof(RTLHEAP_VERIFIER), RTL_HEAP_VERIFIER_TAG);

	if (!pRtlHeapVerifier)
		return NULL;

	RtlZeroMemory(pRtlHeapVerifier, sizeof(RTLHEAP_VERIFIER));

	InitializeListHead(&pRtlHeapVerifier->pBinaryNameList);
	ExInitializeFastMutex(&pRtlHeapVerifier->kMutex);

	//Создаем пустой список логов
	pRtlHeapVerifier->pMemoryLogList = CreateMemoryLogList();

	if (!pRtlHeapVerifier->pMemoryLogList)
	{
		FreeRtlHeapVerifier(pRtlHeapVerifier);

		W32VrfDbgPrint(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "CreateMemoryLogList Error\n");

		return NULL;
	}

	//Callback для создание процессов
	nStatus = PsSetCreateProcessNotifyRoutineEx(RtlHVCreateProcessRoutine, FALSE);

	if (nStatus != STATUS_SUCCESS)
	{
		FreeRtlHeapVerifier(pRtlHeapVerifier);

		W32VrfDbgPrint(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "PsSetCreateProcessNotifyRoutineEx Error\n");

		return NULL;
	}

	KAPC_STATE	ApcState;

	AttachToNamedProcess(DEFAULY_W32_PROCESS, &ApcState);

	pRtlHeapVerifier->pWin32kImportTableHeapHook		= HookRtlHeapFunctions("win32k.sys", pRtlHeapVerifier->pMemoryLogList);
	pRtlHeapVerifier->pWin32kBaseImportTableHeapHook	= HookRtlHeapFunctions("win32kbase.sys", pRtlHeapVerifier->pMemoryLogList);
	pRtlHeapVerifier->pWin32kFullImportTableHeapHook	= HookRtlHeapFunctions("win32kfull.sys", pRtlHeapVerifier->pMemoryLogList);

	KeUnstackDetachProcess(&ApcState);

	if ((pRtlHeapVerifier->pWin32kImportTableHeapHook		== NULL) &&
		(pRtlHeapVerifier->pWin32kBaseImportTableHeapHook	== NULL) &&
		(pRtlHeapVerifier->pWin32kFullImportTableHeapHook	== NULL))
	{
		FreeRtlHeapVerifier(pRtlHeapVerifier);

		W32VrfDbgPrint(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "HookHeapFunctions Error\n");

		return NULL;
	}

	W32VrfDbgPrint(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "pWin32kImportTableHeapHook 0x%p\n", pRtlHeapVerifier->pWin32kImportTableHeapHook);
	W32VrfDbgPrint(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "pWin32kImportTableHeapHook 0x%p\n", pRtlHeapVerifier->pWin32kBaseImportTableHeapHook);
	W32VrfDbgPrint(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "pWin32kImportTableHeapHook 0x%p\n", pRtlHeapVerifier->pWin32kFullImportTableHeapHook);

	pRtlHeapVerifier->bInited = TRUE;

	g_pHeapVerifier = pRtlHeapVerifier;

	return pRtlHeapVerifier;
}

VOID
FreeRtlHeapVerifier(
	_In_ PRTLHEAP_VERIFIER pRtlHeapVerifier
)
{
	if (pRtlHeapVerifier)
	{
		pRtlHeapVerifier->bInited = FALSE;

		PsSetCreateProcessNotifyRoutineEx(RtlHVCreateProcessRoutine, TRUE);

		KAPC_STATE	ApcState;

		AttachToNamedProcess(DEFAULY_W32_PROCESS, &ApcState);

		UnhookRtlHeapFunctions(pRtlHeapVerifier->pWin32kImportTableHeapHook);
		pRtlHeapVerifier->pWin32kImportTableHeapHook = NULL;

		UnhookRtlHeapFunctions(pRtlHeapVerifier->pWin32kBaseImportTableHeapHook);
		pRtlHeapVerifier->pWin32kBaseImportTableHeapHook = NULL;

		UnhookRtlHeapFunctions(pRtlHeapVerifier->pWin32kFullImportTableHeapHook);
		pRtlHeapVerifier->pWin32kFullImportTableHeapHook = NULL;

		KeUnstackDetachProcess(&ApcState);

		g_pHeapVerifier = NULL;

		if (pRtlHeapVerifier->pMemoryLogList)
		{
			FreeMemoryLogList(pRtlHeapVerifier->pMemoryLogList);
			pRtlHeapVerifier->pMemoryLogList = NULL;
		}
		
		FreeBinaryNamesList(pRtlHeapVerifier);

		ExFreePoolWithTag(pRtlHeapVerifier, RTL_HEAP_VERIFIER_TAG);
	}
}

VOID
FreeBinaryNamesList(
	_In_ PRTLHEAP_VERIFIER	pHeapVerifier
)
{
	PBINARY_NAME_ENTRY pFirstItem = NULL;

	if (pHeapVerifier)
	{
		ExAcquireFastMutex(&pHeapVerifier->kMutex);

		while (!IsListEmpty(&pHeapVerifier->pBinaryNameList))
		{
			pFirstItem = (PBINARY_NAME_ENTRY)RemoveHeadList(&pHeapVerifier->pBinaryNameList);

			if (pFirstItem)
			{
				RtlFreeUnicodeString(&pFirstItem->ProcessName);
				ExFreePoolWithTag(pFirstItem, RTL_HEAP_VERIFIER_TAG);
			}
		}

		ExReleaseFastMutex(&pHeapVerifier->kMutex);
	}
}

//Получить имя процесса из Create info
NTSTATUS
GetProcessNameFromCreateInfo(
	_In_	PPS_CREATE_NOTIFY_INFO	pCurProcessCreateInfo,
	_Out_	PUNICODE_STRING	pCurProcessName
)
{
	if (!pCurProcessCreateInfo ||
		!pCurProcessName)
		return STATUS_INVALID_PARAMETER;

	return
		FltParseFileName(	pCurProcessCreateInfo->ImageFileName,
							NULL,
							NULL,
							pCurProcessName);
}

BOOL
IsProcessNameInBinaryList(
	_In_ PRTLHEAP_VERIFIER	pHeapVerifier,
	_In_ PUNICODE_STRING pCreatedProcessName
)
{
	PBINARY_NAME_ENTRY pNameEntry;

	if (!pHeapVerifier ||
		!pCreatedProcessName)
		return FALSE;

	ExAcquireFastMutex(&pHeapVerifier->kMutex);

	//Пройдемся по процессам
	for (pNameEntry = (PBINARY_NAME_ENTRY)pHeapVerifier->pBinaryNameList.Flink;
		//Признак конца - элемент указывает на голову
		pNameEntry != (PBINARY_NAME_ENTRY)&pHeapVerifier->pBinaryNameList;
		//Следующий элемент списка
		pNameEntry = (PBINARY_NAME_ENTRY)pNameEntry->ListEntry.Flink)
	{
		if (!pNameEntry)
			break;

		//Запущен процесс, который нас интересует
		if (RtlEqualUnicodeString(&pNameEntry->ProcessName, pCreatedProcessName, FALSE))
		{
			ExReleaseFastMutex(&pHeapVerifier->kMutex);

			return TRUE;
		}
	};

	ExReleaseFastMutex(&pHeapVerifier->kMutex);

	return FALSE;
}

NTSTATUS
AddProcessBinaryName(
	_In_ PRTLHEAP_VERIFIER	pHeapVerifier,
	_In_ wchar_t* pProcessName,
	_In_ ULONG ulProcessNameLen
)
{
	if (!pHeapVerifier	||
		!pProcessName	||
		!ulProcessNameLen)
		return STATUS_INVALID_PARAMETER;

	//Если длина имени меньше 4 байт или не кратна 2 байтам - это не нормальная UNICODE строка
	if(	ulProcessNameLen < 4 ||
		ulProcessNameLen % 2)
		return STATUS_INVALID_PARAMETER;

	//Чтобы строка с именем процесса гарантированно заканчивалась двумя 0 - поместим ее во временный буфер
	//Который закончим двумя 0
	wchar_t* pTempProcName = ExAllocatePoolWithTag(NonPagedPool, ulProcessNameLen + 2, RTL_HEAP_VERIFIER_TAG);

	if (!pTempProcName)
		return STATUS_MEMORY_NOT_ALLOCATED;

	RtlZeroBytes(pTempProcName, ulProcessNameLen + 2);
	RtlCopyBytes(pTempProcName, pProcessName, ulProcessNameLen);

	PBINARY_NAME_ENTRY pBinaryNameEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(BINARY_NAME_ENTRY), RTL_HEAP_VERIFIER_TAG);

	if (!pBinaryNameEntry)
	{
		ExFreePoolWithTag(pTempProcName, RTL_HEAP_VERIFIER_TAG);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	if (!RtlCreateUnicodeString(&pBinaryNameEntry->ProcessName, pTempProcName))
	{
		ExFreePoolWithTag(pTempProcName, RTL_HEAP_VERIFIER_TAG);
		ExFreePoolWithTag(pBinaryNameEntry, RTL_HEAP_VERIFIER_TAG);

		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	if (IsProcessNameInBinaryList(pHeapVerifier, &pBinaryNameEntry->ProcessName))
	{
		ExFreePoolWithTag(pTempProcName, RTL_HEAP_VERIFIER_TAG);
		RtlFreeUnicodeString(&pBinaryNameEntry->ProcessName);
		ExFreePoolWithTag(pBinaryNameEntry, RTL_HEAP_VERIFIER_TAG);

		return STATUS_SUCCESS;
	}

	//Процесса нет - добавляем
	InitializeListHead(&pBinaryNameEntry->ListEntry);

	ExAcquireFastMutex(&pHeapVerifier->kMutex);
	InsertTailList(&pHeapVerifier->pBinaryNameList, &pBinaryNameEntry->ListEntry);
	ExReleaseFastMutex(&pHeapVerifier->kMutex);

	ExFreePoolWithTag(pTempProcName, RTL_HEAP_VERIFIER_TAG);

	return STATUS_SUCCESS;
}

NTSTATUS
RemoveProcessBinaryName(
	_In_ PRTLHEAP_VERIFIER	pHeapVerifier,
	_In_ wchar_t* pProcessName,
	_In_ ULONG ulProcessNameLen
)
{
	PBINARY_NAME_ENTRY pNameEntry;

	UNICODE_STRING ProcessName;

	if (!pHeapVerifier ||
		!pProcessName ||
		!ulProcessNameLen)
		return STATUS_INVALID_PARAMETER;

	//Если длина имени меньше 4 байт или не кратна 2 байтам - это не нормальная UNICODE строка
	if (ulProcessNameLen < 4 ||
		ulProcessNameLen % 2)
		return STATUS_INVALID_PARAMETER;

	//Чтобы строка с именем процесса гарантированно заканчивалась двумя 0 - поместим ее во временный буфер
	//Который закончим двумя 0
	wchar_t* pTempProcName = ExAllocatePoolWithTag(NonPagedPool, ulProcessNameLen + 2, RTL_HEAP_VERIFIER_TAG);

	if (!pTempProcName)
		return STATUS_MEMORY_NOT_ALLOCATED;

	RtlZeroBytes(pTempProcName, ulProcessNameLen + 2);
	RtlCopyBytes(pTempProcName, pProcessName, ulProcessNameLen);

	if (!RtlCreateUnicodeString(&ProcessName, pTempProcName))
	{
		ExFreePoolWithTag(pTempProcName, RTL_HEAP_VERIFIER_TAG);

		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	ExAcquireFastMutex(&pHeapVerifier->kMutex);

	//Пройдемся по процессам
	for (pNameEntry = (PBINARY_NAME_ENTRY)pHeapVerifier->pBinaryNameList.Flink;
		//Признак конца - элемент указывает на голову
		pNameEntry != (PBINARY_NAME_ENTRY)&pHeapVerifier->pBinaryNameList;
		//Следующий элемент списка
		pNameEntry = (PBINARY_NAME_ENTRY)pNameEntry->ListEntry.Flink)
	{
		if (!pNameEntry)
			break;

		//Запущен процесс, который нас интересует
		if (RtlEqualUnicodeString(&pNameEntry->ProcessName, &ProcessName, FALSE))
		{
			RemoveEntryList(&pNameEntry->ListEntry);

			RtlFreeUnicodeString(&ProcessName);
			RtlFreeUnicodeString(&pNameEntry->ProcessName);
			ExFreePoolWithTag(pTempProcName, RTL_HEAP_VERIFIER_TAG);
			ExFreePoolWithTag(pNameEntry, RTL_HEAP_VERIFIER_TAG);

			ExReleaseFastMutex(&pHeapVerifier->kMutex);

			return STATUS_SUCCESS;
		}
	};

	RtlFreeUnicodeString(&ProcessName);
	ExFreePoolWithTag(pTempProcName, RTL_HEAP_VERIFIER_TAG);

	ExReleaseFastMutex(&pHeapVerifier->kMutex);

	return STATUS_NOT_FOUND;
}

VOID
RtlHVCreateProcessRoutine(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	NTSTATUS nStatus;
	UNICODE_STRING	CurProcessName;

	UNREFERENCED_PARAMETER(ProcessId);

	if (!g_pHeapVerifier)
		return;

	if (!g_pHeapVerifier->bInited)
		return;

	//Процесс только создается
	if (CreateInfo)
	{
		//Получаем имя создаваемого процесса
		nStatus = GetProcessNameFromCreateInfo(CreateInfo, &CurProcessName);

		if (nStatus == STATUS_SUCCESS)
		{
			if (IsProcessNameInBinaryList(g_pHeapVerifier, &CurProcessName))
			{
				nStatus = AddMemoryLogForProcess(g_pHeapVerifier->pMemoryLogList, Process);
				
				if (nStatus != STATUS_SUCCESS)
				{
					W32VrfDbgPrint(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "AddMemoryLogForProcess Error\n");
				}
			}
		}
	}
	else
	{
		RemoveMemoryLogByEprocess(g_pHeapVerifier->pMemoryLogList, Process);
	}
}