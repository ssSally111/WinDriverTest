#include "test.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	DbgPrint("[DriverTest] DriverEntry\n");

	for (size_t i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
	{
		pDriverObject->MajorFunction[i] = MajorHandle;
	}
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControl;
	pDriverObject->DriverUnload = DriverUnload;

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING SymLinkName;
	UNICODE_STRING DeviceName;

	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	status = IoCreateDevice(pDriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevice);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[DriverTest] CreateDevice Failed\n");
		return status;
	}

	RtlInitUnicodeString(&SymLinkName, SYM_LINK_NAME);
	status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[DriverTest] CreateSymbolicLink Failed\n");
		IoDeleteDevice(pDevice);
		return status;
	}

	pDevice->Flags |= DO_BUFFERED_IO;

	return status;
}

NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING SymLinkName;
	RtlInitUnicodeString(&SymLinkName, SYM_LINK_NAME);

	IoDeleteSymbolicLink(&SymLinkName);
	IoDeleteDevice(pDriverObject->DeviceObject);

	DbgPrint("[DriverTest] DriverUnload\n");
	return STATUS_SUCCESS;
}

NTSTATUS MajorHandle(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS DriverControl(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	PIO_STACK_LOCATION pIrps = IoGetCurrentIrpStackLocation(pIrp);
	ULONG inLength = pIrps->Parameters.DeviceIoControl.InputBufferLength;
	ULONG optLength = pIrps->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG CODE = pIrps->Parameters.DeviceIoControl.IoControlCode;
	ULONG info = 0;

	switch (CODE)
	{
	case IOCTL_TEST:
	{
		DbgPrint("[DriverTest] DriverControl IOCTL_TEST");

		PVOID pBuff = pIrp->AssociatedIrp.SystemBuffer;

		ULONG pid = *(PLONG)(pBuff);
		NTSTATUS status = KillProcess(pid);
		memset(pBuff, status, 8);
		info = 8;

		break;
	}
	case ENUMERATE_MODULES:
		DbgPrint("[DriverTest] DriverControl ENUMERATE_MODULES");

		EnumerateModules();

		PVOID pBuff = pIrp->AssociatedIrp.SystemBuffer;
		memset(pBuff, status, 10);
		info = 10;

		break;
	default:
		break;
	}

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = info;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	DbgPrint("[DriverTest] DriverControl SUCCESS");
	return status;
}

NTSTATUS DriverRead(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	PIO_STACK_LOCATION pIoStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG ulReadLength = pIoStack->Parameters.Read.Length;
	PVOID lpAddr = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = ulReadLength;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	if (!lpAddr)
	{
		return status;
	}

	//memset(pIrp->AssociatedIrp.SystemBuffer, 0x0C, ulReadLength);
	memset(lpAddr, 0x61, ulReadLength - 2);
	((PWCHAR)lpAddr)[ulReadLength - 1] = L'\0';

	DbgPrint("[DriverTest] DriverRead SUCCESS");
	return status;
}

NTSTATUS DriverWrite(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	DbgPrint("[DriverTest] DriverWrite SUCCESS");
	return status;
}

// 杀进程
NTSTATUS KillProcess(ULONG pid)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE ProcessHandle;
	OBJECT_ATTRIBUTES ObjAttr;
	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = 0;

	InitializeObjectAttributes(&ObjAttr, 0, 0, 0, 0);
	status = ZwOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &ObjAttr, &cid);
	if (NT_SUCCESS(status))
	{
		ZwTerminateProcess(ProcessHandle, status);
		ZwClose(ProcessHandle);
	}

	DbgPrint("[DriverTest] KillProcess PID: %d", pid);
	return status;
}

// 获取PEB
PPEB GetPebAddress()
{
	PPEB peb = NULL;
#ifdef _WIN64
	peb = (PPEB)__readgsqword(0x60);
#else
	peb = (PPEB)__readfsdword(0x30);
#endif
	return peb;
}

// 模块地址
NTSTATUS EnumerateModules()
{
	NTSTATUS status = STATUS_SUCCESS;

	PPEB pPeb = GetPebAddress();
	if (!pPeb)
	{
		KdPrint(("[DriverTest] PPEB is null..."));
		return status;
	}
	// TODO: Existing problem

	PPEB_LDR_DATA pLdr = pPeb->Ldr;
	if (!pLdr)
	{
		KdPrint(("[DriverTest] PPEB_LDR_DATA is null..."));
		return status;
	}

	PLIST_ENTRY moduleList = &(pLdr->InLoadOrderModuleList);
	PLIST_ENTRY moduleEntry = moduleList->Flink;

	while (moduleEntry != moduleList)
	{
		PLDR_MODULE module = CONTAINING_RECORD(moduleEntry, LDR_MODULE, InLoadOrderModuleList);

		KdPrint(("[DriverTest] Module FullPath:%wZ\tBaseAddress:0x%p",
			module->FullDllName, module->BaseAddress));

		moduleEntry = moduleEntry->Flink;
	}

	KdPrint(("[DriverTest] EnumerateModules"));
	return status;
}

// 模块地址
NTSTATUS EnumerateModulesEx()
{
	NTSTATUS status = STATUS_SUCCESS;

	ULONG length = 0;
	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, NULL, &length);
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{

		PVOID p = ExAllocatePool2(POOL_FLAG_NON_PAGED, length, 'ISQZ');
		if (!p) {
			KdPrint(("[DriverTest] EnumerateModulesEx ExAllocatePool Fail [size:%d], \
				There is not enough memory in the pool to satisfy the request...\n", length));
			return status;
		}

		status = ZwQuerySystemInformation(SystemModuleInformation, p, length, &length);
		if (!NT_SUCCESS(status))
		{
			ExFreePoolWithTag(p, 'ISQZ');
			KdPrint(("[DriverTest] EnumerateModulesEx ZwQuerySystemInformation [2] Fail %d ...\n", status));
			return status;
		}

		PSYSTEM_MODULE_INFORMATION pSystemModelInformation = (PSYSTEM_MODULE_INFORMATION)p;
		for (ULONG i = 0; i < pSystemModelInformation->ModulesCount; i++)
		{
			KdPrint(("[DriverTest] EnumerateModulesEx SystemModelInformation: Name:%-50s Base:0x%p\n",
				pSystemModelInformation->Modules[i].Name, pSystemModelInformation->Modules[i].ImageBaseAddress));
		}

		ExFreePoolWithTag(p, 'ISQZ');
	}
	else {
		KdPrint(("[DriverTest] EnumerateModulesEx ZwQuerySystemInformation [1] Fail %d ...\n", status));
	}

	return status;
}