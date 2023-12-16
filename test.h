#pragma once

#include <ntddk.h>


#define DEVICE_NAME L"\\Device\\DriverTest"
#define SYM_LINK_NAME L"\\??\\DriverControlsTest"
#define DRIVER_NAME L"\\??\\C:\\Users\\ab\\Desktop\\DriverDemo.sys"

#define IOCTL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ENUMERATE_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define LOAD_SYS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef unsigned char       BYTE;
typedef NTSTATUS(*FnDriverEntry)(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPathy);

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemNextEventIdInformation,
    SystemEventIdsInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
    SystemPowerInformationEx,
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;


// system module
typedef struct _SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	INT64                Id;
	INT64                Rank;
	INT64                w018;
	INT64                NameOffset;
	BYTE                 Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

// system module information
typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[0];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

// LDR_MODULE
typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

// PEB_LDR_DATA 
typedef struct _PEB_LDR_DATA {
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// PEB
typedef struct _PEB {
    BYTE InheritedAddressSpace;
    BYTE ReadImageFileExecOptions;
    BYTE BeingDebugged;
    BYTE Spare;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    PVOID NtGlobalFlag;
    PVOID CriticalSectionTimeout;
    PVOID HeapSegmentReserve;
    PVOID HeapSegmentCommit;
    PVOID HeapDeCommitTotalFreeThreshold;
    PVOID HeapDeCommitFreeBlockThreshold;
    PVOID LockProcessAffinity;
    PVOID SetProcessAffinityThread;
    PVOID _EndOfStructure;
} PEB, * PPEB;

// LOAD DRIVER INFORMATION
typedef struct _SYSTEM_LOAD_GDI_DRIVER_INFORMATION {
    UNICODE_STRING SysName;
    ULONG               DriverStart;
    PVOID               DriverInfo;
    PVOID               DriverEntry;
    PVOID               ExportDirectory;
    ULONG               SizeOfImage;
} SYSTEM_LOAD_GDI_DRIVER_INFORMATION, * PSYSTEM_LOAD_GDI_DRIVER_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT OPTIONAL PULONG ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI ZwSetSystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN PVOID                SystemInformation,
    IN ULONG                SystemInformationLength
);


NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS MajorHandle(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS DriverControl(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS DriverRead(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS DriverWrite(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS KillProcess(ULONG pid);
NTSTATUS EnumerateModules();
NTSTATUS EnumerateModulesEx();
VOID Initiatory(PDRIVER_OBJECT pDriverObject);
NTSTATUS Load();