#pragma once

#include <ntddk.h>


#define DEVICE_NAME L"\\Device\\DriverTest"
#define SYM_LINK_NAME L"\\??\\DriverControlsTest"

#define IOCTL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ENUMERATE_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define SystemModuleInformation 0x0B


typedef unsigned char       BYTE;


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


NTSYSAPI
NTSTATUS
NTAPI ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT OPTIONAL PULONG ReturnLength
);


NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS MajorHandle(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS DriverControl(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS DriverRead(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS DriverWrite(PDEVICE_OBJECT pDriverObject, PIRP pIrp);
NTSTATUS KillProcess(ULONG pid);
NTSTATUS EnumerateModules();
NTSTATUS EnumerateModulesEx();