#pragma once

#define MEMORY_LOGGER_TAG	'TGOL'

#define MAX_LOG_SIZE	0x6400000
#define KERNEL_MEM_TAG	'GOLK'

#define LAST_LOG_RECORD	"LAST_RECORD"

#define LOG_DELIMETER	"<----->\r\n"

//Записи в логе
typedef struct _MEMORY_LOG_RECORD
{
	//Список
	LIST_ENTRY	ListEntry;
	//Размер данной записи
	SIZE_T		cbSize;
	//Собственно туловище записи
	BYTE		pRecord[ANYSIZE_ARRAY];
}MEMORY_LOG_RECORD,*PMEMORY_LOG_RECORD;

//Часть, расположенная в user mode памяти
typedef struct _USER_MODE_LOG_BUFFER
{
	//Tag по котором можно найти лог в user mode памяти
	DWORD		dwTag;
	//Kernel Mode указатель на лог 
	//PPROCESS_MEMORY_LOG
	PVOID		pMemoryLog;
}USER_MODE_LOG_BUFFER, *PUSER_MODE_LOG_BUFFER;

//Структура логера
typedef struct _PROCESS_MEMORY_LOG
{
	//Список
	LIST_ENTRY	ListEntry;
	//Процесс, в контексте которого пишеться лог
	PEPROCESS	pEprocess;
	//Имя процесса
	UNICODE_STRING pProcessName;
	//Указатель на User Mode память
	PUSER_MODE_LOG_BUFFER	pUserModeLogBuffer;
	//Количество записей в логе
	DWORD		dwRecordsAmount;
	//Общий размер занятого пространства
	SIZE_T		UsedSize;
	//Список записей в логе
	LIST_ENTRY	LogRecordsList;
	//Блокировка
	FAST_MUTEX	kMutex;

}PROCESS_MEMORY_LOG, *PPROCESS_MEMORY_LOG;

//Список логов всех процессов
typedef struct _MEMORY_LOG_LIST
{
	//Список всех логов
	LIST_ENTRY	ListHead;

	ULONG	uMemLogCount;

	//Блокировка
	FAST_MUTEX	kMutex;

}MEMORY_LOG_LIST, *PMEMORY_LOG_LIST;

//Memory log list functions
PMEMORY_LOG_LIST
CreateMemoryLogList();

VOID
FreeMemoryLogList(
	_In_ PMEMORY_LOG_LIST pMemoryLogList
);

//Memory log functions for process
NTSTATUS
AddMemoryLogForProcess(
	_In_ PMEMORY_LOG_LIST pMemoryLogList,
	_In_ PEPROCESS pEprocess
);

VOID
RemoveMemoryLogByEprocess(
	_In_ PMEMORY_LOG_LIST pMemoryLogList,
	_In_ PEPROCESS pEprocess
);

PPROCESS_MEMORY_LOG
GetMemoryLogByEProcess(
	_In_ PMEMORY_LOG_LIST pMemoryLogList,
	_In_ PEPROCESS pEprocess
);

VOID
FreeMemoryLog(
	_In_ PPROCESS_MEMORY_LOG	pMemLog
);

//Log record functions
PMEMORY_LOG_RECORD
AllocateMemoryLogRecord(
	_In_ SIZE_T	Size
);

VOID
FreeMemoryLogRecord(
	_In_ PMEMORY_LOG_RECORD pMemoryLogRecord
);

NTSTATUS
AddToMemoryLog(
	_In_ PPROCESS_MEMORY_LOG pMemLog,
	_In_ PBYTE	pBuffer,
	_In_ SIZE_T	Size
);
