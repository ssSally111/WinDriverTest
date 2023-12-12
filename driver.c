#include <ntddk.h>


#define DEVICE_NAME L"\\Device\\DriverTest"
#define SYM_LINK_NAME L"\\??\\DriverControlsTest"
#define IOCTL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)


NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS MajorHandle(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS DriverControl(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS DriverRead(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS DriverWrite(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS KillProcess(ULONG pid);

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