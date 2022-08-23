#include "..\common.h"

PIMPORT_TABLE_HOOK
HookImportTableEntry(
	_In_ char*	cImportDriverName,
	_In_ char*	cExportDriverName,
	_In_ char*	cFunctionName,
	_In_ PVOID	pHandler
)
{
	PIMPORT_TABLE_HOOK pImportTableHook;
	PVOID	pImportAddr;

	if (strlen(cImportDriverName)	> MAX_PATH ||
		strlen(cExportDriverName)	> MAX_PATH ||
		strlen(cFunctionName)		> MAX_PATH)
		return NULL;

	pImportTableHook = ExAllocatePoolWithTag(NonPagedPool, sizeof(IMPORT_TABLE_HOOK), IMPORT_HOOK_TAG);

	if (!pImportTableHook)
		return NULL;

	RtlZeroMemory(pImportTableHook, sizeof(IMPORT_TABLE_HOOK));

	strcpy_s(pImportTableHook->cImportDriverName, sizeof(pImportTableHook->cImportDriverName), cImportDriverName );
	strcpy_s(pImportTableHook->cExportDriverName, sizeof(pImportTableHook->cExportDriverName), cExportDriverName );
	strcpy_s(pImportTableHook->cFunctionName, sizeof(pImportTableHook->cFunctionName), cFunctionName);

	pImportAddr = KernelGetImportAddress(cImportDriverName, cExportDriverName, cFunctionName);
	if (!pImportAddr)
	{
		ExFreePoolWithTag(pImportTableHook, IMPORT_HOOK_TAG);

		W32VrfDbgPrint(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s not found\n", cFunctionName);
		return NULL;
	}

	W32VrfDbgPrint(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%p ----> %p : %s\n",pImportAddr,*(PVOID*)pImportAddr,cFunctionName);

	//Сохраняем старые оригинальные значения функций
	InterlockedExchange64((__int64*)&pImportTableHook->f_pOriginalAddress, *(PULONG64)pImportAddr);

	__disable_interrupt();
	__clear_wp();

	//Ставим хуки в таблицу импорта.
	InterlockedExchange64((__int64*)pImportAddr, (__int64)pHandler);

	pImportTableHook->f_pHookAddress = pHandler;

	__set_wp();
	__enable_interrupt();

	pImportTableHook->bActive = TRUE;

	return pImportTableHook;
}

NTSTATUS
UnhookImportTableEntry(
	_In_ PIMPORT_TABLE_HOOK	pImportTableHook
)
{
	if (!pImportTableHook)
		return STATUS_INVALID_PARAMETER;

	if (!pImportTableHook->bActive)
	{
		ExFreePoolWithTag(pImportTableHook, IMPORT_HOOK_TAG);
		return STATUS_SUCCESS;
	}

	PVOID pImportAddr = KernelGetImportAddress(pImportTableHook->cImportDriverName, pImportTableHook->cExportDriverName, pImportTableHook->cFunctionName);

	__disable_interrupt();
	__clear_wp();

	//Ставим хуки в таблицу импорта.
	InterlockedExchange64((__int64*)pImportAddr, (__int64)pImportTableHook->f_pOriginalAddress);

	__set_wp();
	__enable_interrupt();

	ExFreePoolWithTag(pImportTableHook, IMPORT_HOOK_TAG);

	return STATUS_SUCCESS;
}