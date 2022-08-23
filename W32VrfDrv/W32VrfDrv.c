#include "common.h"

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT	DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{

	NTSTATUS nStatus;

	UNICODE_STRING  devName;
	UNICODE_STRING symLinkName;

	PDEVICE_OBJECT	PBDevice;
	PW32VRFDRV_EXT		pW32VrfExt;

	nStatus = STATUS_UNSUCCESSFUL;

	DriverObject->DriverUnload = W32VrfDrvUnload;

	
	DriverObject->MajorFunction[IRP_MJ_CREATE]			= W32VrfDrvCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE]			= W32VrfDrvClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]	= W32VrfDeviceIoControl;

	RtlInitUnicodeString(&devName, DEVICE_NAME);

	nStatus = IoCreateDevice(	DriverObject,
								sizeof(W32VRFDRV_EXT),
								&devName,
								FILE_DEVICE_UNKNOWN,
								0,
								FALSE,
								&PBDevice);

	if (!NT_SUCCESS(nStatus))
		return nStatus;

	pW32VrfExt = (PW32VRFDRV_EXT)PBDevice->DeviceExtension;

	RtlInitUnicodeString(&symLinkName, SYM_LINK);
	pW32VrfExt->ustrSymLinkName = symLinkName;

	nStatus = IoCreateSymbolicLink(&symLinkName, &devName);
	if (!NT_SUCCESS(nStatus))
	{
		IoDeleteDevice(PBDevice);
		return nStatus;
	}

	pW32VrfExt->pRegistryPath = RegistryPath;

	pW32VrfExt->pHVDev = PBDevice;

	pW32VrfExt->bOpened = FALSE;

	ExInitializeFastMutex(&pW32VrfExt->kMutex);

	W32VrfDbgPrint(DPFLTR_DEFAULT_ID,
		DPFLTR_ERROR_LEVEL,
		"W32VrfDrv Load\r\n");

	return nStatus;
}

VOID
W32VrfDrvUnload(
	_In_ PDRIVER_OBJECT pDriverObject
)
{
	PDEVICE_OBJECT	pNextDevObj;
	PW32VRFDRV_EXT	pW32VrfExt;
	PUNICODE_STRING pLinkName;

	pNextDevObj = pDriverObject->DeviceObject;

	pW32VrfExt = (PW32VRFDRV_EXT)pNextDevObj->DeviceExtension;

	ExAcquireFastMutex(&pW32VrfExt->kMutex);

	if (pW32VrfExt->pRtlHV)
	{
		FreeRtlHeapVerifier(pW32VrfExt->pRtlHV);
		pW32VrfExt->pRtlHV = NULL;
	}

	ExReleaseFastMutex(&pW32VrfExt->kMutex);

	pLinkName = &pW32VrfExt->ustrSymLinkName;
	pNextDevObj = pNextDevObj->NextDevice;

	IoDeleteSymbolicLink(pLinkName);
	IoDeleteDevice(pW32VrfExt->pHVDev);

	W32VrfDbgPrint(DPFLTR_DEFAULT_ID,
		DPFLTR_ERROR_LEVEL,
		"W32VrfDrv Exit\r\n");
}

NTSTATUS
W32VrfDrvCreate(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP pIrp
)
{
	NTSTATUS nStatus = STATUS_SUCCESS;

	PIO_STACK_LOCATION	IoStackLocation;
	PW32VRFDRV_EXT		pW32VrfExt;

	IoStackLocation = IoGetCurrentIrpStackLocation(pIrp);

	pW32VrfExt = DeviceObject->DeviceExtension;

	ExAcquireFastMutex(&pW32VrfExt->kMutex);

	pW32VrfExt->bOpened = TRUE;

	pIrp->IoStatus.Status = nStatus;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	ExReleaseFastMutex(&pW32VrfExt->kMutex);

	return nStatus;
}

NTSTATUS
W32VrfDrvClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP pIrp
)
{
	NTSTATUS nStatus = STATUS_SUCCESS;

	PIO_STACK_LOCATION	IoStackLocation;
	PW32VRFDRV_EXT		pW32VrfExt;

	IoStackLocation = IoGetCurrentIrpStackLocation(pIrp);

	pW32VrfExt = DeviceObject->DeviceExtension;

	ExAcquireFastMutex(&pW32VrfExt->kMutex);

	pW32VrfExt->bOpened = FALSE;

	pIrp->IoStatus.Status = nStatus;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	ExReleaseFastMutex(&pW32VrfExt->kMutex);

	return nStatus;
}

NTSTATUS
W32VrfDeviceIoControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP pIrp
)
{
	PIO_STACK_LOCATION	IoStackLocation;
	PW32VRFDRV_EXT		pW32VrfExt;

	//KAPC_STATE	apcState;

	NTSTATUS	nStatus;

	DWORD	dwIOctlCode;
	PBYTE	pConfig;

	IoStackLocation = IoGetCurrentIrpStackLocation(pIrp);

	pW32VrfExt = DeviceObject->DeviceExtension;

	pIrp->IoStatus.Information = 0;
	nStatus = STATUS_UNSUCCESSFUL;

	dwIOctlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;

	pConfig = NULL;

	ExAcquireFastMutex(&pW32VrfExt->kMutex);

	//Обработать буфер
	switch (dwIOctlCode)
	{
		//Активируем хук на выделение/освобождение памяти
		case ENABLE_MEMORY_HOOK_IOCTL:
		{
			pW32VrfExt->pRtlHV = CreateRtlHeapVerifier();

			if (pW32VrfExt->pRtlHV)
				nStatus = STATUS_SUCCESS;

			break;
		}

		//Снимаем хук на выделение/освобождение памяти
		case DISABLE_MEMORY_HOOK_IOCTL:
		{
			if (pW32VrfExt->pRtlHV)
			{
				FreeRtlHeapVerifier(pW32VrfExt->pRtlHV);
				pW32VrfExt->pRtlHV = NULL;

				nStatus = STATUS_SUCCESS;
			}

			break;
		}

		//Добавляем имя процесса, который надо мониторить
		case ADD_PROCESS_HOOK_IOCTL:
		{
			if (!pW32VrfExt->pRtlHV)
				break;

			if (!pW32VrfExt->pRtlHV->bInited)
				break;

			nStatus = AddProcessBinaryName(	pW32VrfExt->pRtlHV, 
											pIrp->AssociatedIrp.SystemBuffer, 
											IoStackLocation->Parameters.DeviceIoControl.InputBufferLength);

			break;
		}

		//Удаляем процесс из мониторинга
		case REMOVE_PROCESS_HOOK_IOCTL:
		{
			if (!pW32VrfExt->pRtlHV)
				break;

			if (!pW32VrfExt->pRtlHV->bInited)
				break;

			nStatus = RemoveProcessBinaryName(	pW32VrfExt->pRtlHV,
												pIrp->AssociatedIrp.SystemBuffer,
												IoStackLocation->Parameters.DeviceIoControl.InputBufferLength);

			break;
		}

		default:
		{
			nStatus = STATUS_NOT_SUPPORTED;
			break;
		}
	}

	pIrp->IoStatus.Status = nStatus;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	ExReleaseFastMutex(&pW32VrfExt->kMutex);

	return nStatus;
}