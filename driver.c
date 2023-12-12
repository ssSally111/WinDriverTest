#include <ntddk.h>


#define DEVICE_NAME L"\\Device\\DriverTest"
#define SYM_LINK_NAME L"\\??\\DriverControlsTest"


NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS DriverRead(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS DriverCreate(PDEVICE_OBJECT pDriverObject, PIRP pIrp);

PDEVICE_OBJECT pDevice;
UNICODE_STRING SymLinkName;

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	DbgPrint("[DriverTest] DriverEntry\n");

	pDriverObject->DriverUnload = DriverUnload;
	pDriverObject->MajorFunction[IRP_MJ_READ] = DriverRead;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;

	NTSTATUS status = STATUS_SUCCESS;

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
	IoDeleteSymbolicLink(&SymLinkName);
	IoDeleteDevice(pDevice);

	DbgPrint("[DriverTest] DriverUnload\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverCreate(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	DbgPrint("[DriverTest] DriverCreate OK");
	return status;
}

NTSTATUS DriverRead(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	PIO_STACK_LOCATION pIoStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG ulReadLength = pIoStack->Parameters.Read.Length;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = ulReadLength;
	memset(pIrp->AssociatedIrp.SystemBuffer, 0x0C, ulReadLength);
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	DbgPrint("[DriverTest] DriverRead OK");
	return status;
}