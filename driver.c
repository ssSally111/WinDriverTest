#include <ntddk.h>


#define DEVICE_NAME L"\\Device\\DriverTest"
#define SYM_LINK_NAME L"\\??\\DriverControlsTest"

#define IOCTL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ENUMERATE_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define SystemModuleInformation 0x0B


typedef unsigned char       BYTE;
typedef VOID (NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (VOID);

typedef struct _MODULE_INFO {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID BaseAddress;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullPathName;
	UNICODE_STRING ModuleName;
} MODULE_INFO, * PMODULE_INFO;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	union {
		UCHAR BitField[5];
	};
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	ULONG64 SubSystemData;
} PEB, * PPEB;



//typedef struct _PEB {
//	BOOLEAN InheritedAddressSpace;
//	BOOLEAN ReadImageFileExecOptions;
//	BOOLEAN BeingDebugged;
//	union {
//		BOOLEAN BitField;
//		struct {
//			BOOLEAN ImageUsesLargePages : 1;
//			BOOLEAN IsProtectedProcess : 1;
//			BOOLEAN IsImageDynamicallyRelocated : 1;
//			BOOLEAN SkipPatchingUser32Forwarders : 1;
//			BOOLEAN IsPackagedProcess : 1;
//			BOOLEAN IsAppContainer : 1;
//			BOOLEAN IsProtectedProcessLight : 1;
//			BOOLEAN IsLongPathAwareProcess : 1;
//		};
//	};
//	HANDLE Mutant;
//	PVOID ImageBaseAddress;
//	PPEB_LDR_DATA Ldr;
//	// ...
//} PEB, * PPEB;


NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS MajorHandle(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS DriverControl(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS DriverRead(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS DriverWrite(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS KillProcess(ULONG pid);
NTSTATUS EnumerateModules();

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

// 获取 PEB 结构的地址
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

	PPEB peb = GetPebAddress();
	if (peb == NULL)
	{
		KdPrint(("peb is null..."));
		return status;
	}
	KdPrint(("peb %p\n", peb));

	PPEB_LDR_DATA ldr = peb->Ldr;
	if (ldr == NULL)
	{
		KdPrint(("ldr is null..."));
		return status;
	}
	KdPrint(("ldr %p\n", ldr));
	return status;

	PLIST_ENTRY moduleList = &(ldr->InLoadOrderModuleList);
	PLIST_ENTRY moduleEntry = moduleList->Flink;

	KdPrint(("moduleList %p\n", moduleList));
	KdPrint(("moduleEntry %p\n", moduleEntry));

	while (moduleEntry != moduleList)
	{
		PMODULE_INFO moduleInfo = CONTAINING_RECORD(moduleEntry, MODULE_INFO, InLoadOrderModuleList);

		KdPrint(("Module BaseAddress: %p\n", moduleInfo->BaseAddress));
		KdPrint(("Module Size: %lu\n", moduleInfo->SizeOfImage));
		KdPrint(("Module FullPath: %wZ\n", moduleInfo->FullPathName));
		KdPrint(("Module Name: %wZ\n", moduleInfo->ModuleName));

		moduleEntry = moduleEntry->Flink;
	}

	KdPrint(("[DriverTest] EnumerateModules"));
	return status;
}