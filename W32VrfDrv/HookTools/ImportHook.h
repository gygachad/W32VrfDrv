#pragma once

#define IMPORT_HOOK_TAG 'THMI'

typedef struct _IMPORT_TABLE_HOOK
{
	//Активность хука
	BOOL	bActive;
	//Имя драйвера, таблицу импорта которого захукали
	char	cImportDriverName[MAX_PATH];
	//Имя драйвера, из которого импортируется функция
	char	cExportDriverName[MAX_PATH];
	//Имя функции
	char	cFunctionName[MAX_PATH];
	//Оригинальный адрес
	PVOID f_pOriginalAddress;
	//Адрес хука
	PVOID f_pHookAddress;
}IMPORT_TABLE_HOOK, *PIMPORT_TABLE_HOOK;

//Поставить хук на запись в таблице импорта
PIMPORT_TABLE_HOOK
HookImportTableEntry(
	_In_ char*	cImportDriverName,
	_In_ char*	cExportDriverName,
	_In_ char*	cFunctionName,
	_In_ PVOID	pHandler
);

//Убрать хук с записи в таблице импорта
NTSTATUS
UnhookImportTableEntry(
	_In_ PIMPORT_TABLE_HOOK	pImportTableHook
);
