#pragma once

#include "ntdll.h"
#include "defines.h"

#define SYSCALL_STUB_SIZE 12

//
// SYSCALL_STUB bytes (x64) — 12 bytes:
//   0x4C, 0x8B, 0xD1             mov r10, rcx
//   0xB8, [SSN little-endian]    mov eax, SSN
//   0x0F, 0x05                   syscall
//   0xC3                         ret
//
#define SYSCALL_STUB_OFFSET_SSN 4

typedef struct _SYSCALL_ENTRY
{
	PVOID  pSyscallGadget;
	DWORD  dwSSN;
	PBYTE  pSyscallStub;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

//
// Function pointer typedefs
//
typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(
	HANDLE   ProcessHandle,
	PVOID*   BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T  RegionSize,
	ULONG    AllocationType,
	ULONG    Protect
	);

typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(
	HANDLE  ProcessHandle,
	PVOID*  BaseAddress,
	PSIZE_T RegionSize,
	ULONG   NewProtect,
	PULONG  OldProtect
	);

typedef NTSTATUS (NTAPI *fnNtFreeVirtualMemory)(
	HANDLE  ProcessHandle,
	PVOID*  BaseAddress,
	PSIZE_T RegionSize,
	ULONG   FreeType
	);

typedef NTSTATUS (NTAPI *fnNtWriteVirtualMemory)(
	HANDLE  ProcessHandle,
	PVOID   BaseAddress,
	PVOID   Buffer,
	SIZE_T  BufferSize,
	PSIZE_T BytesWritten
	);

typedef NTSTATUS (NTAPI *fnNtReadVirtualMemory)(
	HANDLE  ProcessHandle,
	PVOID   BaseAddress,
	PVOID   Buffer,
	SIZE_T  BufferSize,
	PSIZE_T BytesRead
	);

typedef NTSTATUS (NTAPI *fnNtCreateThreadEx)(
	PHANDLE      ThreadHandle,
	ACCESS_MASK  DesiredAccess,
	PVOID        ObjectAttributes,
	HANDLE       ProcessHandle,
	PVOID        StartRoutine,
	PVOID        Argument,
	ULONG        CreateFlags,
	SIZE_T       ZeroBits,
	SIZE_T       StackSize,
	SIZE_T       MaximumStackSize,
	PVOID        AttributeList
	);

typedef NTSTATUS (NTAPI *fnNtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
	);

typedef NTSTATUS (NTAPI *fnNtClose)(
	HANDLE Handle
	);

typedef NTSTATUS (NTAPI *fnNtWaitForSingleObject)(
	HANDLE         Handle,
	BOOLEAN        Alertable,
	PLARGE_INTEGER Timeout
	);

typedef NTSTATUS (NTAPI *fnNtDelayExecution)(
	BOOLEAN        Alertable,
	PLARGE_INTEGER Interval
	);

typedef NTSTATUS (NTAPI *fnNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

typedef NTSTATUS (NTAPI *fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

typedef NTSTATUS (NTAPI *fnNtTerminateProcess)(
	HANDLE   ProcessHandle,
	NTSTATUS ExitStatus
	);

typedef NTSTATUS (NTAPI *fnNtTerminateThread)(
	HANDLE   ThreadHandle,
	NTSTATUS ExitStatus
	);

typedef NTSTATUS (NTAPI *fnNtOpenProcessToken)(
	HANDLE      ProcessHandle,
	ACCESS_MASK DesiredAccess,
	PHANDLE     TokenHandle
	);

typedef NTSTATUS (NTAPI *fnNtOpenThreadToken)(
	HANDLE      ThreadHandle,
	ACCESS_MASK DesiredAccess,
	BOOLEAN     OpenAsSelf,
	PHANDLE     TokenHandle
	);

typedef NTSTATUS (NTAPI *fnNtGetContextThread)(
	HANDLE   ThreadHandle,
	PCONTEXT ThreadContext
	);

typedef NTSTATUS (NTAPI *fnNtSetContextThread)(
	HANDLE   ThreadHandle,
	PCONTEXT ThreadContext
	);

typedef NTSTATUS (NTAPI *fnNtResumeThread)(
	HANDLE ThreadHandle,
	PULONG SuspendCount
	);

typedef NTSTATUS (NTAPI *fnNtCreateSection)(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER     MaximumSize,
	ULONG              SectionPageProtection,
	ULONG              AllocationAttributes,
	HANDLE             FileHandle
	);

typedef NTSTATUS (NTAPI *fnNtMapViewOfSection)(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID*          BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	ULONG           InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
	);

typedef NTSTATUS (NTAPI *fnNtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID  BaseAddress
	);

typedef NTSTATUS (NTAPI *fnNtQueryVirtualMemory)(
	HANDLE                    ProcessHandle,
	PVOID                     BaseAddress,
	MEMORY_INFORMATION_CLASS  MemoryInformationClass,
	PVOID                     MemoryInformation,
	SIZE_T                    MemoryInformationLength,
	PSIZE_T                   ReturnLength
	);

typedef NTSTATUS (NTAPI *fnNtDuplicateObject)(
	HANDLE      SourceProcessHandle,
	HANDLE      SourceHandle,
	HANDLE      TargetProcessHandle,
	PHANDLE     TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG       HandleAttributes,
	ULONG       Options
	);

typedef NTSTATUS (NTAPI *fnNtCreateFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
	);

typedef NTSTATUS (NTAPI *fnNtReadFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PVOID            ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
	);

typedef NTSTATUS (NTAPI *fnNtWriteFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PVOID            ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
	);

typedef NTSTATUS (NTAPI *fnNtDeviceIoControlFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PVOID            ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG            IoControlCode,
	PVOID            InputBuffer,
	ULONG            InputBufferLength,
	PVOID            OutputBuffer,
	ULONG            OutputBufferLength
	);

typedef NTSTATUS (NTAPI *fnNtQueueApcThread)(
	HANDLE ThreadHandle,
	PVOID  ApcRoutine,
	PVOID  SystemArgument1,
	PVOID  SystemArgument2,
	PVOID  SystemArgument3
	);

//
// Syscall table
//
typedef struct _SYSCALL_TABLE
{
	SYSCALL_ENTRY ntAllocateVirtualMemory;
	SYSCALL_ENTRY ntProtectVirtualMemory;
	SYSCALL_ENTRY ntFreeVirtualMemory;
	SYSCALL_ENTRY ntWriteVirtualMemory;
	SYSCALL_ENTRY ntReadVirtualMemory;
	SYSCALL_ENTRY ntCreateThreadEx;
	SYSCALL_ENTRY ntOpenProcess;
	SYSCALL_ENTRY ntClose;
	SYSCALL_ENTRY ntWaitForSingleObject;
	SYSCALL_ENTRY ntDelayExecution;
	SYSCALL_ENTRY ntQueryInformationProcess;
	SYSCALL_ENTRY ntQuerySystemInformation;
	SYSCALL_ENTRY ntTerminateProcess;
	SYSCALL_ENTRY ntTerminateThread;
	SYSCALL_ENTRY ntOpenProcessToken;
	SYSCALL_ENTRY ntOpenThreadToken;
	SYSCALL_ENTRY ntGetContextThread;
	SYSCALL_ENTRY ntSetContextThread;
	SYSCALL_ENTRY ntResumeThread;
	SYSCALL_ENTRY ntCreateSection;
	SYSCALL_ENTRY ntMapViewOfSection;
	SYSCALL_ENTRY ntUnmapViewOfSection;
	SYSCALL_ENTRY ntQueryVirtualMemory;
	SYSCALL_ENTRY ntDuplicateObject;
	SYSCALL_ENTRY ntCreateFile;
	SYSCALL_ENTRY ntReadFile;
	SYSCALL_ENTRY ntWriteFile;
	SYSCALL_ENTRY ntDeviceIoControlFile;
	SYSCALL_ENTRY ntQueueApcThread;
} SYSCALL_TABLE, *PSYSCALL_TABLE;

//
// Global syscall table instance
//
extern SYSCALL_TABLE* g_Syscalls;

//
// NtCurrentProcess pseudo-handle
//
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

//
// InitSyscalls - resolves all SSNs and builds stub gadgets
//
BOOL InitSyscalls();

//
// GetSyscallNumber - retrieve SSN from an Nt* function address
//
DWORD GetSyscallNumber(PVOID pNtFunc);

//
// Inline wrapper helpers: cast stub to fn* and call
//
#define SYSCALL_INVOKE(entry, fnType, ...) \
	((fnType)((entry).pSyscallStub))(__VA_ARGS__)

//
// Inline syscall wrappers
//
__forceinline NTSTATUS NtAllocateVirtualMemory_SYSCALL(
	HANDLE hProcess, PVOID* pBaseAddress, ULONG_PTR ZeroBits,
	PSIZE_T pRegionSize, ULONG AllocationType, ULONG Protect)
{
	return SYSCALL_INVOKE(g_Syscalls->ntAllocateVirtualMemory, fnNtAllocateVirtualMemory,
		hProcess, pBaseAddress, ZeroBits, pRegionSize, AllocationType, Protect);
}

__forceinline NTSTATUS NtProtectVirtualMemory_SYSCALL(
	HANDLE hProcess, PVOID* pBaseAddress, PSIZE_T pRegionSize,
	ULONG NewProtect, PULONG OldProtect)
{
	return SYSCALL_INVOKE(g_Syscalls->ntProtectVirtualMemory, fnNtProtectVirtualMemory,
		hProcess, pBaseAddress, pRegionSize, NewProtect, OldProtect);
}

__forceinline NTSTATUS NtFreeVirtualMemory_SYSCALL(
	HANDLE hProcess, PVOID* pBaseAddress, PSIZE_T pRegionSize, ULONG FreeType)
{
	return SYSCALL_INVOKE(g_Syscalls->ntFreeVirtualMemory, fnNtFreeVirtualMemory,
		hProcess, pBaseAddress, pRegionSize, FreeType);
}

__forceinline NTSTATUS NtWriteVirtualMemory_SYSCALL(
	HANDLE hProcess, PVOID pBaseAddress, PVOID pBuffer, SIZE_T BufferSize, PSIZE_T pBytesWritten)
{
	return SYSCALL_INVOKE(g_Syscalls->ntWriteVirtualMemory, fnNtWriteVirtualMemory,
		hProcess, pBaseAddress, pBuffer, BufferSize, pBytesWritten);
}

__forceinline NTSTATUS NtReadVirtualMemory_SYSCALL(
	HANDLE hProcess, PVOID pBaseAddress, PVOID pBuffer, SIZE_T BufferSize, PSIZE_T pBytesRead)
{
	return SYSCALL_INVOKE(g_Syscalls->ntReadVirtualMemory, fnNtReadVirtualMemory,
		hProcess, pBaseAddress, pBuffer, BufferSize, pBytesRead);
}

__forceinline NTSTATUS NtCreateThreadEx_SYSCALL(
	PHANDLE pThreadHandle, ACCESS_MASK DesiredAccess, PVOID pObjectAttributes,
	HANDLE hProcess, PVOID pStartRoutine, PVOID pArgument, ULONG CreateFlags,
	SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID pAttributeList)
{
	return SYSCALL_INVOKE(g_Syscalls->ntCreateThreadEx, fnNtCreateThreadEx,
		pThreadHandle, DesiredAccess, pObjectAttributes, hProcess, pStartRoutine,
		pArgument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, pAttributeList);
}

__forceinline NTSTATUS NtOpenProcess_SYSCALL(
	PHANDLE pProcessHandle, ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES pObjectAttributes, PCLIENT_ID pClientId)
{
	return SYSCALL_INVOKE(g_Syscalls->ntOpenProcess, fnNtOpenProcess,
		pProcessHandle, DesiredAccess, pObjectAttributes, pClientId);
}

__forceinline NTSTATUS NtClose_SYSCALL(HANDLE hHandle)
{
	return SYSCALL_INVOKE(g_Syscalls->ntClose, fnNtClose, hHandle);
}

__forceinline NTSTATUS NtWaitForSingleObject_SYSCALL(
	HANDLE hHandle, BOOLEAN bAlertable, PLARGE_INTEGER pTimeout)
{
	return SYSCALL_INVOKE(g_Syscalls->ntWaitForSingleObject, fnNtWaitForSingleObject,
		hHandle, bAlertable, pTimeout);
}

__forceinline NTSTATUS NtDelayExecution_SYSCALL(BOOLEAN bAlertable, PLARGE_INTEGER pInterval)
{
	return SYSCALL_INVOKE(g_Syscalls->ntDelayExecution, fnNtDelayExecution,
		bAlertable, pInterval);
}

__forceinline NTSTATUS NtQueryInformationProcess_SYSCALL(
	HANDLE hProcess, PROCESSINFOCLASS ProcessInformationClass,
	PVOID pProcessInformation, ULONG ProcessInformationLength, PULONG pReturnLength)
{
	return SYSCALL_INVOKE(g_Syscalls->ntQueryInformationProcess, fnNtQueryInformationProcess,
		hProcess, ProcessInformationClass, pProcessInformation, ProcessInformationLength, pReturnLength);
}

__forceinline NTSTATUS NtQuerySystemInformation_SYSCALL(
	SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID pSystemInformation,
	ULONG SystemInformationLength, PULONG pReturnLength)
{
	return SYSCALL_INVOKE(g_Syscalls->ntQuerySystemInformation, fnNtQuerySystemInformation,
		SystemInformationClass, pSystemInformation, SystemInformationLength, pReturnLength);
}

__forceinline NTSTATUS NtTerminateProcess_SYSCALL(HANDLE hProcess, NTSTATUS ExitStatus)
{
	return SYSCALL_INVOKE(g_Syscalls->ntTerminateProcess, fnNtTerminateProcess,
		hProcess, ExitStatus);
}

__forceinline NTSTATUS NtTerminateThread_SYSCALL(HANDLE hThread, NTSTATUS ExitStatus)
{
	return SYSCALL_INVOKE(g_Syscalls->ntTerminateThread, fnNtTerminateThread,
		hThread, ExitStatus);
}

__forceinline NTSTATUS NtOpenProcessToken_SYSCALL(
	HANDLE hProcess, ACCESS_MASK DesiredAccess, PHANDLE pTokenHandle)
{
	return SYSCALL_INVOKE(g_Syscalls->ntOpenProcessToken, fnNtOpenProcessToken,
		hProcess, DesiredAccess, pTokenHandle);
}

__forceinline NTSTATUS NtOpenThreadToken_SYSCALL(
	HANDLE hThread, ACCESS_MASK DesiredAccess, BOOLEAN bOpenAsSelf, PHANDLE pTokenHandle)
{
	return SYSCALL_INVOKE(g_Syscalls->ntOpenThreadToken, fnNtOpenThreadToken,
		hThread, DesiredAccess, bOpenAsSelf, pTokenHandle);
}

__forceinline NTSTATUS NtGetContextThread_SYSCALL(HANDLE hThread, PCONTEXT pContext)
{
	return SYSCALL_INVOKE(g_Syscalls->ntGetContextThread, fnNtGetContextThread,
		hThread, pContext);
}

__forceinline NTSTATUS NtSetContextThread_SYSCALL(HANDLE hThread, PCONTEXT pContext)
{
	return SYSCALL_INVOKE(g_Syscalls->ntSetContextThread, fnNtSetContextThread,
		hThread, pContext);
}

__forceinline NTSTATUS NtResumeThread_SYSCALL(HANDLE hThread, PULONG pSuspendCount)
{
	return SYSCALL_INVOKE(g_Syscalls->ntResumeThread, fnNtResumeThread,
		hThread, pSuspendCount);
}

__forceinline NTSTATUS NtCreateSection_SYSCALL(
	PHANDLE pSectionHandle, ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES pObjectAttributes, PLARGE_INTEGER pMaximumSize,
	ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE hFile)
{
	return SYSCALL_INVOKE(g_Syscalls->ntCreateSection, fnNtCreateSection,
		pSectionHandle, DesiredAccess, pObjectAttributes, pMaximumSize,
		SectionPageProtection, AllocationAttributes, hFile);
}

__forceinline NTSTATUS NtMapViewOfSection_SYSCALL(
	HANDLE hSection, HANDLE hProcess, PVOID* ppBaseAddress, ULONG_PTR ZeroBits,
	SIZE_T CommitSize, PLARGE_INTEGER pSectionOffset, PSIZE_T pViewSize,
	ULONG InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
	return SYSCALL_INVOKE(g_Syscalls->ntMapViewOfSection, fnNtMapViewOfSection,
		hSection, hProcess, ppBaseAddress, ZeroBits, CommitSize, pSectionOffset,
		pViewSize, InheritDisposition, AllocationType, Win32Protect);
}

__forceinline NTSTATUS NtUnmapViewOfSection_SYSCALL(HANDLE hProcess, PVOID pBaseAddress)
{
	return SYSCALL_INVOKE(g_Syscalls->ntUnmapViewOfSection, fnNtUnmapViewOfSection,
		hProcess, pBaseAddress);
}

__forceinline NTSTATUS NtQueryVirtualMemory_SYSCALL(
	HANDLE hProcess, PVOID pBaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID pMemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T pReturnLength)
{
	return SYSCALL_INVOKE(g_Syscalls->ntQueryVirtualMemory, fnNtQueryVirtualMemory,
		hProcess, pBaseAddress, MemoryInformationClass, pMemoryInformation,
		MemoryInformationLength, pReturnLength);
}

__forceinline NTSTATUS NtDuplicateObject_SYSCALL(
	HANDLE hSourceProcess, HANDLE hSourceHandle, HANDLE hTargetProcess,
	PHANDLE pTargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{
	return SYSCALL_INVOKE(g_Syscalls->ntDuplicateObject, fnNtDuplicateObject,
		hSourceProcess, hSourceHandle, hTargetProcess, pTargetHandle,
		DesiredAccess, HandleAttributes, Options);
}

__forceinline NTSTATUS NtCreateFile_SYSCALL(
	PHANDLE pFileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES pObjectAttributes,
	PIO_STATUS_BLOCK pIoStatusBlock, PLARGE_INTEGER pAllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
	PVOID pEaBuffer, ULONG EaLength)
{
	return SYSCALL_INVOKE(g_Syscalls->ntCreateFile, fnNtCreateFile,
		pFileHandle, DesiredAccess, pObjectAttributes, pIoStatusBlock, pAllocationSize,
		FileAttributes, ShareAccess, CreateDisposition, CreateOptions, pEaBuffer, EaLength);
}

__forceinline NTSTATUS NtReadFile_SYSCALL(
	HANDLE hFile, HANDLE hEvent, PVOID pApcRoutine, PVOID pApcContext,
	PIO_STATUS_BLOCK pIoStatusBlock, PVOID pBuffer, ULONG Length,
	PLARGE_INTEGER pByteOffset, PULONG pKey)
{
	return SYSCALL_INVOKE(g_Syscalls->ntReadFile, fnNtReadFile,
		hFile, hEvent, pApcRoutine, pApcContext, pIoStatusBlock, pBuffer,
		Length, pByteOffset, pKey);
}

__forceinline NTSTATUS NtWriteFile_SYSCALL(
	HANDLE hFile, HANDLE hEvent, PVOID pApcRoutine, PVOID pApcContext,
	PIO_STATUS_BLOCK pIoStatusBlock, PVOID pBuffer, ULONG Length,
	PLARGE_INTEGER pByteOffset, PULONG pKey)
{
	return SYSCALL_INVOKE(g_Syscalls->ntWriteFile, fnNtWriteFile,
		hFile, hEvent, pApcRoutine, pApcContext, pIoStatusBlock, pBuffer,
		Length, pByteOffset, pKey);
}

__forceinline NTSTATUS NtDeviceIoControlFile_SYSCALL(
	HANDLE hFile, HANDLE hEvent, PVOID pApcRoutine, PVOID pApcContext,
	PIO_STATUS_BLOCK pIoStatusBlock, ULONG IoControlCode,
	PVOID pInputBuffer, ULONG InputBufferLength,
	PVOID pOutputBuffer, ULONG OutputBufferLength)
{
	return SYSCALL_INVOKE(g_Syscalls->ntDeviceIoControlFile, fnNtDeviceIoControlFile,
		hFile, hEvent, pApcRoutine, pApcContext, pIoStatusBlock, IoControlCode,
		pInputBuffer, InputBufferLength, pOutputBuffer, OutputBufferLength);
}

__forceinline NTSTATUS NtQueueApcThread_SYSCALL(
	HANDLE hThread, PVOID pApcRoutine, PVOID pSystemArgument1,
	PVOID pSystemArgument2, PVOID pSystemArgument3)
{
	return SYSCALL_INVOKE(g_Syscalls->ntQueueApcThread, fnNtQueueApcThread,
		hThread, pApcRoutine, pSystemArgument1, pSystemArgument2, pSystemArgument3);
}
