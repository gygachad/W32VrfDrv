#include "../common.h"

PVOID
GetSysInf(
	_In_ SYSTEM_INFORMATION_CLASS InfoClass
)
{
	NTSTATUS ns;
	ULONG RetSize, Size = 0x100;
	PVOID Info;

	while (TRUE)
	{
		if ((Info = ExAllocatePoolWithTag(NonPagedPool, Size, WIN_TOOL_TAG)) == NULL)
		{
			W32VrfDbgPrint(	DPFLTR_DEFAULT_ID,
						DPFLTR_ERROR_LEVEL, 
						"ExAllocatePool() fails\n");
			return NULL;
		}

		RetSize = 0;
		//ns = NtQuerySystemInformation(InfoClass, Info, Size, &RetSize);
		ns = ZwQuerySystemInformation(InfoClass, Info, Size, &RetSize);
		if (ns == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(Info);
			Info = NULL;

			if (RetSize > 0)
			{
				Size = RetSize + 0x100;
			}
			else
				break;
		}
		else
			break;
	}

	if (!NT_SUCCESS(ns))
	{
		W32VrfDbgPrint(	DPFLTR_DEFAULT_ID,
					DPFLTR_ERROR_LEVEL, 
					"ZwQuerySystemInformation() fails; status: 0x%.8x\n", ns);

		if (Info)
			ExFreePoolWithTag(Info, WIN_TOOL_TAG);

		return NULL;
	}

	return Info;
}

PVOID
GetKernelModuleBase(
	_In_ char *ModuleName
)
{
	PVOID pModuleBase = NULL;
	UNICODE_STRING usCommonHalName, usCommonNtName;
	NTSTATUS nStatus;

	RtlInitUnicodeString(&usCommonHalName, L"hal.dll");
	RtlInitUnicodeString(&usCommonNtName, L"ntoskrnl.exe");

#define HAL_NAMES_NUM 6
	wchar_t *wcHalNames[] =
	{
		L"hal.dll",      // Non-ACPI PIC HAL 
		L"halacpi.dll",  // ACPI PIC HAL
		L"halapic.dll",  // Non-ACPI APIC UP HAL
		L"halmps.dll",   // Non-ACPI APIC MP HAL
		L"halaacpi.dll", // ACPI APIC UP HAL
		L"halmacpi.dll"  // ACPI APIC MP HAL
	};

#define NT_NAMES_NUM 4
	wchar_t *wcNtNames[] =
	{
		L"ntoskrnl.exe", // UP
		L"ntkrnlpa.exe", // UP PAE
		L"ntkrnlmp.exe", // MP
		L"ntkrpamp.exe"  // MP PAE
	};

	if(!ModuleName)
		return NULL;

	PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)GetSysInf(SystemModuleInformation);
	if (Info)
	{
		ANSI_STRING asModuleName;
		UNICODE_STRING usModuleName;

		RtlInitAnsiString(&asModuleName, ModuleName);

		nStatus = RtlAnsiStringToUnicodeString(&usModuleName, &asModuleName, TRUE);
		if (NT_SUCCESS(nStatus))
		{
			for (ULONG i = 0; i < Info->NumberOfModules; i++)
			{
				ANSI_STRING asEnumModuleName;
				UNICODE_STRING usEnumModuleName;

				RtlInitAnsiString(
					&asEnumModuleName,
					(char *)Info->Modules[i].FullPathName + Info->Modules[i].OffsetToFileName
				);

				nStatus = RtlAnsiStringToUnicodeString(&usEnumModuleName, &asEnumModuleName, TRUE);
				if (NT_SUCCESS(nStatus))
				{
					if (RtlEqualUnicodeString(&usModuleName, &usCommonHalName, TRUE))
					{
						// hal.dll passed as module name
						for (int i_m = 0; i_m < HAL_NAMES_NUM; i_m++)
						{
							UNICODE_STRING usHalName;
							RtlInitUnicodeString(&usHalName, wcHalNames[i_m]);

							// compare module name from list with known HAL module name
							if (RtlEqualUnicodeString(&usEnumModuleName, &usHalName, TRUE))
							{
								pModuleBase = (PVOID)Info->Modules[i].ImageBase;
								break;
							}
						}
					}
					else if (RtlEqualUnicodeString(&usModuleName, &usCommonNtName, TRUE))
					{
						// ntoskrnl.exe passed as module name
						for (int i_m = 0; i_m < NT_NAMES_NUM; i_m++)
						{
							UNICODE_STRING usNtName;
							RtlInitUnicodeString(&usNtName, wcNtNames[i_m]);

							// compare module name from list with known kernel module name
							if (RtlEqualUnicodeString(&usEnumModuleName, &usNtName, TRUE))
							{
								pModuleBase = (PVOID)Info->Modules[i].ImageBase;
								break;
							}
						}
					}
					else if (RtlEqualUnicodeString(&usModuleName, &usEnumModuleName, TRUE))
					{
						pModuleBase = (PVOID)Info->Modules[i].ImageBase;
					}

					RtlFreeUnicodeString(&usEnumModuleName);

					if (pModuleBase)
					{
						// module is found
						break;
					}
				}
			}

			RtlFreeUnicodeString(&usModuleName);
		}

		ExFreePool(Info);
	}

	return pModuleBase;
}

PVOID
KernelGetExportAddress(
	_In_ char *ModuleName,
	_In_ char *lpszFunctionName
)
{
	__try
	{
		PVOID	ExportAddress		= NULL;
		ULONG	ulFunctionOffset	= 0x0;

		PVOID Image = GetKernelModuleBase(ModuleName);

		if (!Image)
			return 0;

		PIMAGE_EXPORT_DIRECTORY pExport = NULL;

		PIMAGE_NT_HEADERS32 pHeaders32 = (PIMAGE_NT_HEADERS32)
			((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

		if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
		{
			// 32-bit image
			if (pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
			{
				pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(	Image,
															pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
				);
			}
		}
		else if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
		{
			// 64-bit image
			PIMAGE_NT_HEADERS64 pHeaders64 = (PIMAGE_NT_HEADERS64)
				((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

			if (pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
			{
				pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(	Image,
															pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
				);
			}
		}
		else
		{
			W32VrfDbgPrint(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, __FUNCTION__"() ERROR: Unkown machine type\n");
			return NULL;
		}

		if (pExport)
		{
			PULONG AddressOfFunctions = (PULONG)RVATOVA(Image, pExport->AddressOfFunctions);
			PSHORT AddrOfOrdinals = (PSHORT)RVATOVA(Image, pExport->AddressOfNameOrdinals);
			PULONG AddressOfNames = (PULONG)RVATOVA(Image, pExport->AddressOfNames);

			for (ULONG i = 0; i < pExport->NumberOfFunctions; i++)
			{
				if (!strcmp((char *)RVATOVA(Image, AddressOfNames[i]), lpszFunctionName))
				{
					ulFunctionOffset = AddressOfFunctions[AddrOfOrdinals[i]];
					ExportAddress = (PVOID)RVATOVA(Image, ulFunctionOffset);

					W32VrfDbgPrint(	DPFLTR_DEFAULT_ID,
								DPFLTR_ERROR_LEVEL, 
								"%s ! %s ---> 0x%llx\n",
								ModuleName,
								lpszFunctionName,
								ExportAddress);

					break;
				}
			}
		}
		else
		{
			W32VrfDbgPrint(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "WARNING: Export directory not found\n");
		}

		return ExportAddress;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		W32VrfDbgPrint(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, __FUNCTION__"() EXCEPTION\n");
	}

	return 0;
}

PVOID
KernelGetImportAddress(
	_In_ char *ModuleName,
	_In_ char *ImporterModuleName,
	_In_ char *lpszFunctionName
)
{
	PVOID	Image;
	PBYTE	ulBase;

	//Заголовок DOS
	PIMAGE_DOS_HEADER			pDosHeader;

	//Заголовок PE
	PIMAGE_NT_HEADERS			pPEHeader;

	//адреса таблцы импорта
	PIMAGE_IMPORT_DESCRIPTOR	pImportTable;

	//обработка таблицы импорта
	PDWORD	RVA;
	PIMAGE_IMPORT_BY_NAME pImportTableChunk;
	PVOID	importFuncAddr;
	DWORD	dwIATIndex;

	PVOID	pImportedFunctionAddr;

	importFuncAddr = NULL;
	pImportedFunctionAddr = NULL;

	Image = GetKernelModuleBase(ModuleName);

	if (!Image)
		return NULL;

	pDosHeader = (PIMAGE_DOS_HEADER)Image;
	pPEHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);

	ulBase = (PBYTE)Image;

	pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(pPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + ulBase);

	while (pImportTable->Name && pImportTable->Name != -1)
	{
		if (strcmp((char*)(pImportTable->Name + ulBase), ImporterModuleName) != 0x0)
		{
			//следующая таблица
			pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pImportTable + sizeof(IMAGE_IMPORT_DESCRIPTOR));
			continue;
		}

		//если импорт идет через IAT
		if (pImportTable->Characteristics)
		{
			RVA = (PDWORD)(pImportTable->OriginalFirstThunk + ulBase);
		}
		else//иначе через таблицу адресов
		{
			RVA = (PDWORD)(pImportTable->FirstThunk + ulBase);
		}

		dwIATIndex = 0;
		//обработка ссылок на таблицу имен функций
		while (*RVA)
		{
			pImportTableChunk = (PIMAGE_IMPORT_BY_NAME)(*RVA + ulBase);

			//Импорт по имени
			if (pImportTableChunk &&
				pImportTableChunk->Name)
			{
				if (strcmp((char*)(pImportTableChunk->Name), lpszFunctionName) == 0x0)
				{
					importFuncAddr = pImportTable->FirstThunk + ulBase + dwIATIndex;
					break;
				}
			}

			//следующий адрес
			*((PDWORD)&RVA) += sizeof(PVOID);
			dwIATIndex += sizeof(PBYTE);

		}

		break;
	}

	if (!importFuncAddr)
		return NULL;

	if (pPEHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		//Оригинальный обработчик
		*((PULONG64)&pImportedFunctionAddr) = (ULONG64)importFuncAddr;
	}

	return
		pImportedFunctionAddr;
}

wchar_t*
GetProcessName(
	_In_ PEPROCESS	pCurProcess
)
{
	PUNICODE_STRING	pImagePathName;

	wchar_t* pName;

	pImagePathName = (PUNICODE_STRING)*((PUNICODE_STRING*)((BYTE*)pCurProcess + _EPROCESS_IMAGE_FILE_NAME_OFFSET));
	if (!(pImagePathName))
		return NULL;

	if (!pImagePathName->Buffer)
		return NULL;

	pName = wcsrchr(pImagePathName->Buffer, '\\') + 1;

	return pName;
}

ULONG64
GetProcessDirectoryTableBase(
	_In_ PEPROCESS	pCurProcess
)
{
	return
		*((ULONG64*)((BYTE*)pCurProcess + 0x28));
}

VOID
SetProcessDirectoryTableBase(
	_In_ PEPROCESS	pCurProcess,
	_In_ PVOID	NewDirBase
)
{
	*((PVOID*)((BYTE*)pCurProcess + 0x28)) = NewDirBase;
}

NTSTATUS
GetKernelModuleBaseAddress(
	_In_  PCHAR		pModuleName,
	_Out_ PULONG64	pStartAddr,
	_Out_ PULONG64	pEndAddr)
{
	NTSTATUS nStatus;

	PVOID	pBuffer;
	ULONG	Size;
	ULONG	ReturnSize;
	
	PRTL_PROCESS_MODULES	pProcessModules;
	RTL_PROCESS_MODULE_INFORMATION	pCurModule;
	ULONG	CurModuleNum;

	pBuffer = NULL;
	ReturnSize = 0x0;
	Size = 0x1000;

	if (!pModuleName	||
		!pStartAddr		||
		!pEndAddr)
		return STATUS_INVALID_PARAMETER;
	do
	{
		pBuffer = ExAllocatePoolWithTag(NonPagedPool, Size, WIN_TOOL_TAG);

		if (!pBuffer)
		{
			nStatus = STATUS_MEMORY_NOT_ALLOCATED;

			break;
		}

		RtlZeroMemory(pBuffer, Size);

		nStatus = ZwQuerySystemInformation(11, pBuffer, Size, &ReturnSize);
		//nStatus = NtQuerySystemInformation(11, pBuffer, Size, &ReturnSize);

		if (nStatus == STATUS_SUCCESS)
			break;

		Size = ReturnSize;

		ExFreePool(pBuffer);
		pBuffer = NULL;

	} while (nStatus == STATUS_INFO_LENGTH_MISMATCH);
	
	if (nStatus != STATUS_SUCCESS)
	{
		if (pBuffer)
			ExFreePool(pBuffer);

		return nStatus;
	}

	//копипаста вован
	pProcessModules = (PRTL_PROCESS_MODULES)pBuffer;

	nStatus = STATUS_NOT_FOUND;

	for (	CurModuleNum = 0x0; 
			CurModuleNum < pProcessModules->NumberOfModules; 
			CurModuleNum++)
	{
		pCurModule = pProcessModules->Modules[CurModuleNum];

		if (memcmp(	pCurModule.FullPathName + pCurModule.OffsetToFileName,
					pModuleName,
					min(strlen(pModuleName), sizeof(pCurModule.FullPathName) - pCurModule.OffsetToFileName)) == 0x0)
		{
			*pStartAddr = (ULONG64)pCurModule.ImageBase;
			*pEndAddr = (ULONG64)pCurModule.ImageBase + pCurModule.ImageSize;

			nStatus = STATUS_SUCCESS;

			break;
		}
	}

	if (pBuffer)
		ExFreePoolWithTag(pBuffer, WIN_TOOL_TAG);

	return nStatus;
}

PHYSICAL_ADDRESS
GetPhysicalAddressForContext(
	_In_ PVOID		pVirtual,
	_In_ ULONG64	pContext
)
{
	PHYSICAL_ADDRESS phys;
	ULONG64 pOldCr3;

	pOldCr3 = __readcr3();

	//Для правильного преобразования адреса сменим таблицу страниц на гостевую
	__writecr3(pContext);
	
	phys = MmGetPhysicalAddress(pVirtual);

	//Вертаем все в зад
	__writecr3(pOldCr3);


	return phys;
}

PVOID
GetFunctionRetAddr(
	_In_ PVOID	pFunctionStart
)
{
	PVOID	pFunctionEnd;
	DWORD	dwCurDword;
	DWORD	dwPattern;

	dwCurDword = 0x0;
	dwPattern = 0x909090c3; //retn; nop; nop; nop;

	pFunctionEnd = NULL;

	if (!pFunctionStart)
		return NULL;

	for (dwCurDword; dwCurDword < PAGE_SIZE; dwCurDword++)
	{
		if (*(PDWORD)((PBYTE)pFunctionStart + dwCurDword) == dwPattern)
		{
			pFunctionEnd = (PBYTE)pFunctionStart + dwCurDword;

			break;
		}
	}

	return pFunctionEnd;
}

PEPROCESS
GetFirstGUIProcess()
{
	PEPROCESS CurrentEproc = NULL;
	PEPROCESS Win32Process = NULL;

	PLIST_ENTRY		ProcessLink;
	SHORT          Pid;

	UNICODE_STRING PsGetProcessWin32Process_name;

	RtlInitUnicodeString(&PsGetProcessWin32Process_name, L"PsGetProcessWin32Process");

	pfPsGetProcessWin32Process_t pfPsGetProcessWin32Process = (pfPsGetProcessWin32Process_t)MmGetSystemRoutineAddress(&PsGetProcessWin32Process_name);

	ProcessLink = NULL;
	Pid = 4;

	//Перебираем все процессы пока не найдем GUI
	while (!Win32Process)
	{
		CurrentEproc = NULL;

		//Не нашлось
		if (Pid == 0xffff)
			break;

		PsLookupProcessByProcessId((HANDLE)Pid, &CurrentEproc);
		Pid++;

		if (!CurrentEproc)
			continue;

		Win32Process = pfPsGetProcessWin32Process(CurrentEproc);
	}

	return CurrentEproc;
}

PEPROCESS
AttachToFirstGUI(
	_Out_ KAPC_STATE* kState
)
{
	PEPROCESS  pGuiProcess;

	ASSERT(kState);

	pGuiProcess = NULL;

	//Находим первый попавшийся ГУЙ
	pGuiProcess = GetFirstGUIProcess();

	if (!pGuiProcess)
	{
		return NULL;
	}

	//Цепляемся к контексту GUI процесса
	KeStackAttachProcess((PRKPROCESS)pGuiProcess, kState);

	return pGuiProcess;
}

PEPROCESS
GetNextProcess(
	_In_ PEPROCESS CurrentEproc
)
{
	PEPROCESS Win32Process;
	PEPROCESS StartEproc;
	int       Count;

	ASSERT(CurrentEproc);

	StartEproc = CurrentEproc;
	Win32Process = NULL;
	Count = 0;

	//Перебираем все процессы пока не найдем GUI
	while (!Win32Process)
	{
		//Не нашлось
		if ((Count >= 1) && (CurrentEproc == StartEproc))
		{
			CurrentEproc = NULL;
			break;
		}

		//Берем следующий процесс из списка
		ASSERT(CurrentEproc);
		CurrentEproc = (PEPROCESS)((PBYTE)(*(PULONG64)((PBYTE)CurrentEproc + _EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET)) - _EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET);

		ASSERT(CurrentEproc);

		Win32Process = (PEPROCESS)*(PULONG64)((PBYTE)CurrentEproc + _EPROCESS_WIN32_PROCESS_OFFSET);
		Count++;
	}

	return CurrentEproc;
}

PEPROCESS
AttachToNamedProcess(
	_In_  char*		procName,
	_Out_ KAPC_STATE*	kState
)
{
	PEPROCESS  pCurrentProcess = NULL;

	UNICODE_STRING PsGetProcessImageFileName_name;

	RtlInitUnicodeString(&PsGetProcessImageFileName_name, L"PsGetProcessImageFileName");

	pfPsGetProcessImageFileName_t pfPsGetProcessImageFileName = (pfPsGetProcessImageFileName_t)MmGetSystemRoutineAddress(&PsGetProcessImageFileName_name);

	if (!pfPsGetProcessImageFileName)
		return NULL;

	//Перебираем все процессы пока не найдем GUI
	for(SHORT Pid = 0; Pid <= 0xffff; Pid++)
	{
		pCurrentProcess = NULL;

		//Не нашлось
		if (Pid == 0xffff)
			break;

		PsLookupProcessByProcessId((HANDLE)Pid, &pCurrentProcess);
		Pid++;

		if (!pCurrentProcess)
			continue;

		char* curProcName = pfPsGetProcessImageFileName(pCurrentProcess);

		if (strcmp(procName, curProcName) == 0x0)
			break;
	}

	//Цепляемся к контексту процесса
	if(pCurrentProcess)
		KeStackAttachProcess((PRKPROCESS)pCurrentProcess, kState);

	return pCurrentProcess;
}

void
DetachFromGUI(
	_In_ PRKAPC_STATE ApcState
)
{
	ASSERT(ApcState);

	//Отцепляемся от GUI процесса
	KeUnstackDetachProcess(ApcState);
}