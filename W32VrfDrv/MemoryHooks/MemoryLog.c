#include "..\common.h"

PMEMORY_LOG_LIST
CreateMemoryLogList()
{
	PMEMORY_LOG_LIST pMemoryLogList = NULL;

	pMemoryLogList = ExAllocatePoolWithTag(NonPagedPool, sizeof(MEMORY_LOG_LIST), MEMORY_LOGGER_TAG);

	if (!pMemoryLogList)
		return NULL;

	InitializeListHead(&pMemoryLogList->ListHead);
	ExInitializeFastMutex(&pMemoryLogList->kMutex);

	pMemoryLogList->uMemLogCount = 0x0;

	return pMemoryLogList;
}

VOID
FreeMemoryLogList(
	_In_ PMEMORY_LOG_LIST pMemoryLogList
)
{
	PPROCESS_MEMORY_LOG pFirstLog = NULL;

	if (pMemoryLogList)
	{
		ExAcquireFastMutex(&pMemoryLogList->kMutex);

		while (!IsListEmpty(&pMemoryLogList->ListHead))
		{
			pFirstLog = (PPROCESS_MEMORY_LOG)RemoveHeadList(&pMemoryLogList->ListHead);

			if (pFirstLog)
			{
				FreeMemoryLog(pFirstLog);
				pMemoryLogList->uMemLogCount--;
			}
		}

		ExReleaseFastMutex(&pMemoryLogList->kMutex);
		ExFreePoolWithTag(pMemoryLogList, MEMORY_LOGGER_TAG);
	}
}

NTSTATUS
AddMemoryLogForProcess(
	_In_ PMEMORY_LOG_LIST pMemoryLogList,
	_In_ PEPROCESS pEprocess
)
{
	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
	PPROCESS_MEMORY_LOG pMemLog = NULL;

	KAPC_STATE ApcState;
	SIZE_T	sRegionSize;

	if (!pMemoryLogList)
		return STATUS_INVALID_PARAMETER;

	pMemLog = ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_MEMORY_LOG), MEMORY_LOGGER_TAG);

	if (!pMemLog)
		return STATUS_INSUFFICIENT_RESOURCES;

	W32VrfDbgPrint(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Create log record for process 0x%llx\n", pEprocess);

	RtlZeroMemory(pMemLog, sizeof(PROCESS_MEMORY_LOG));

	pMemLog->pEprocess = pEprocess;

	sRegionSize = sizeof(USER_MODE_LOG_BUFFER);

	KeStackAttachProcess(pMemLog->pEprocess, &ApcState);

	nStatus = ZwAllocateVirtualMemory(NtCurrentProcess(), &pMemLog->pUserModeLogBuffer, 0, &sRegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (nStatus == STATUS_SUCCESS)
	{
		RtlZeroMemory(pMemLog->pUserModeLogBuffer, sizeof(USER_MODE_LOG_BUFFER));
		InitializeListHead(&pMemLog->LogRecordsList);
		ExInitializeFastMutex(&pMemLog->kMutex);

		pMemLog->pUserModeLogBuffer->dwTag = KERNEL_MEM_TAG;
		pMemLog->pUserModeLogBuffer->pMemoryLog = pMemLog;
	}
	else
	{
		ExFreePoolWithTag(pMemLog, MEMORY_LOGGER_TAG);
	}

	if (pMemLog)
	{
		//Добавляем в список лог для нового процесса
		ExAcquireFastMutex(&pMemoryLogList->kMutex);
		InsertTailList(&pMemoryLogList->ListHead, &pMemLog->ListEntry);
		ExReleaseFastMutex(&pMemoryLogList->kMutex);
		
		pMemoryLogList->uMemLogCount++;
		
		nStatus = STATUS_SUCCESS;
	}

	KeUnstackDetachProcess(&ApcState);

	return nStatus;
}

VOID
RemoveMemoryLogByEprocess(
	_In_ PMEMORY_LOG_LIST pMemoryLogList,
	_In_ PEPROCESS pEprocess
)
{
	PPROCESS_MEMORY_LOG pCurProcessMemoryLog;

	if (!pMemoryLogList ||
		!pEprocess)
		return;

	ExAcquireFastMutex(&pMemoryLogList->kMutex);

	//Пройдемся по процессам
	for (pCurProcessMemoryLog = (PPROCESS_MEMORY_LOG)pMemoryLogList->ListHead.Flink;
		//Признак конца - элемент указывает на голову
		pCurProcessMemoryLog != (PPROCESS_MEMORY_LOG)&pMemoryLogList->ListHead;
		//Следующий элемент списка
		pCurProcessMemoryLog = (PPROCESS_MEMORY_LOG)pCurProcessMemoryLog->ListEntry.Flink)
	{
		//Херь какая то - такого быть не должно
		if (!pCurProcessMemoryLog)
			break;

		//Запущен процесс, который нас интересует
		if (pEprocess == pCurProcessMemoryLog->pEprocess)
		{
			RemoveEntryList(&pCurProcessMemoryLog->ListEntry);
			FreeMemoryLog(pCurProcessMemoryLog);

			ExReleaseFastMutex(&pMemoryLogList->kMutex);

			return;
		}
	};

	ExReleaseFastMutex(&pMemoryLogList->kMutex);

	return;
}

PPROCESS_MEMORY_LOG
GetMemoryLogByEProcess(
	_In_ PMEMORY_LOG_LIST pMemoryLogList,
	_In_ PEPROCESS pEprocess
)
{
	PPROCESS_MEMORY_LOG pCurProcess;

	if (!pMemoryLogList ||
		!pEprocess)
		return NULL;

	if (IsListEmpty(&pMemoryLogList->ListHead))
		return NULL;

	//Пройдемся по процессам
	for (pCurProcess = (PPROCESS_MEMORY_LOG)pMemoryLogList->ListHead.Flink;
		//Признак конца - элемент указывает на голову
		pCurProcess != (PPROCESS_MEMORY_LOG)&pMemoryLogList->ListHead;
		//Следующий элемент списка
		pCurProcess = (PPROCESS_MEMORY_LOG)pCurProcess->ListEntry.Flink)
	{
		if (!pCurProcess)
			break;

		//Запущен процесс, который нас интересует
		if (pEprocess == pCurProcess->pEprocess)
		{
			return
				pCurProcess;
		}
	};

	return NULL;
}

VOID
FreeMemoryLog(
	_In_ PPROCESS_MEMORY_LOG	pMemLog
)
{
	KAPC_STATE ApcState;
	SIZE_T	sRegionSize;

	if (pMemLog)
	{
		if (pMemLog->pUserModeLogBuffer)
		{
			KeStackAttachProcess(pMemLog->pEprocess, &ApcState);

			sRegionSize = sizeof(USER_MODE_LOG_BUFFER);

			ZwFreeVirtualMemory(NtCurrentProcess(), &pMemLog->pUserModeLogBuffer, &sRegionSize, MEM_DECOMMIT);

			KeUnstackDetachProcess(&ApcState);
		}

		W32VrfDbgPrint(DPFLTR_DEFAULT_ID,
			DPFLTR_ERROR_LEVEL,
			"Remove log record from process  0x%llx. Memory log size = 0x%08X, Records amount 0x%08X\r\n",
			pMemLog->pEprocess,
			pMemLog->UsedSize,
			pMemLog->dwRecordsAmount);

		//Free All LogEntry's
		PMEMORY_LOG_RECORD pFirstLogRecord;

		pFirstLogRecord = NULL;

		ExAcquireFastMutex(&pMemLog->kMutex);

		while (!IsListEmpty(&pMemLog->LogRecordsList))
		{
			pFirstLogRecord = (PMEMORY_LOG_RECORD)RemoveHeadList(&pMemLog->LogRecordsList);
			
			if (pFirstLogRecord)
			{
				pMemLog->UsedSize -= pFirstLogRecord->cbSize;
				pMemLog->dwRecordsAmount--;
				FreeMemoryLogRecord(pFirstLogRecord);
			}
		}

		ExReleaseFastMutex(&pMemLog->kMutex);

		ExFreePoolWithTag(pMemLog, MEMORY_LOGGER_TAG);
	}
}

PMEMORY_LOG_RECORD
AllocateMemoryLogRecord(
	_In_ SIZE_T	Size
)
{
	PMEMORY_LOG_RECORD	pMemoryLogRecord;

	pMemoryLogRecord = ExAllocatePoolWithTag(NonPagedPool, sizeof(MEMORY_LOG_RECORD) + Size, MEMORY_LOGGER_TAG);

	if (!pMemoryLogRecord)
		return NULL;

	RtlZeroBytes(pMemoryLogRecord, sizeof(MEMORY_LOG_RECORD));

	InitializeListHead(&pMemoryLogRecord->ListEntry);
	pMemoryLogRecord->cbSize = sizeof(MEMORY_LOG_RECORD) + Size;

	return pMemoryLogRecord;
}

VOID
FreeMemoryLogRecord(
	_In_ PMEMORY_LOG_RECORD pMemoryLogRecord
)
{
	if (pMemoryLogRecord)
		ExFreePoolWithTag(pMemoryLogRecord, MEMORY_LOGGER_TAG);
}

NTSTATUS
AddToMemoryLog(
	PPROCESS_MEMORY_LOG pMemLog,
	PBYTE	pBuffer,
	SIZE_T	Size
)
{
	PMEMORY_LOG_RECORD	pMemoryLogRecord;

	if (!pMemLog |
		!pBuffer)
		return STATUS_INVALID_PARAMETER;

	pMemoryLogRecord = AllocateMemoryLogRecord(Size);

	if (!pMemoryLogRecord)
			return STATUS_MEMORY_NOT_ALLOCATED;

	RtlCopyBytes(pMemoryLogRecord->pRecord, pBuffer, Size);

	if (pMemLog)
	{
		while (pMemLog->UsedSize + pMemoryLogRecord->cbSize > MAX_LOG_SIZE)
		{
			PMEMORY_LOG_RECORD pFirstLogRecord = (PMEMORY_LOG_RECORD)RemoveHeadList(&pMemLog->LogRecordsList);

			if (pFirstLogRecord)
			{
				pMemLog->UsedSize -= pFirstLogRecord->cbSize;
				pMemLog->dwRecordsAmount--;
				FreeMemoryLogRecord(pFirstLogRecord);
			}
		}

		//Добавляем в список новую запись
		ExAcquireFastMutex(&pMemLog->kMutex);
		InsertTailList(&pMemLog->LogRecordsList, &pMemoryLogRecord->ListEntry);
		ExReleaseFastMutex(&pMemLog->kMutex);

		pMemLog->dwRecordsAmount++;
		pMemLog->UsedSize += Size;
	}

	return STATUS_SUCCESS;
}