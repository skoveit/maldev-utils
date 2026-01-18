#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <Tlhelp32.h>
#include "../include/process.h"


BOOL PrintProcesses() {

	DWORD		adwProcesses[1024 * 2],
				dwReturnLen1 = NULL,
				dwReturnLen2 = NULL,
				dwNmbrOfPids = NULL;

	HANDLE		hProcess = NULL;
	HMODULE		hModule = NULL;

	WCHAR		szProc[MAX_PATH];

	// get the array of pid's in the system
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// calculating the number of elements in the array returned 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		// a small check
		if (adwProcesses[i] != NULL) {

			// opening a process handle 
			if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'.
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// if EnumProcessModules succeeded
					// get the name of 'hProcess', and saving it in the 'szProc' variable 
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// printing the process name & its pid
						wprintf(L"[%0.3d] Process \"%s\" - Of Pid : %d \n", i, szProc, adwProcesses[i]);
					}
				}

				// close process handle 
				CloseHandle(hProcess);
			}
		}

		// Iterate through the PIDs array  
	}

	return TRUE;
}

BOOL GetRemoteProcessHandleEnum(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess) {

	DWORD		adwProcesses[1024 * 2],
		dwReturnLen1 = NULL,
		dwReturnLen2 = NULL,
		dwNmbrOfPids = NULL;

	HANDLE		hProcess = NULL;
	HMODULE		hModule = NULL;

	WCHAR		szProc[MAX_PATH];

	// Get the array of pid's in the system
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calculating the number of elements in the array returned 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		// If process is NULL
		if (adwProcesses[i] != NULL) {

			// Opening a process handle 
			if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'.
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// if EnumProcessModules succeeded
					// get the name of 'hProcess', and saving it in the 'szProc' variable 
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// Perform the comparison logic
						if (wcscmp(szProcName, szProc) == 0) {
							// wprintf(L"[+] FOUND \"%s\" - Of Pid : %d \n", szProc, adwProcesses[i]);
							// return by reference
							*pdwPid = adwProcesses[i];
							*phProcess = hProcess;
							break;
						}
					}
				}

				CloseHandle(hProcess);
			}
		}
	}

	// Check if pdwPid or phProcess are NULL
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}
BOOL GetRemoteProcessHandleNt(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess) {

	fnNtQuerySystemInformation		pNtQuerySystemInformation = NULL;
	ULONG							uReturnLen1 = NULL,
									uReturnLen2 = NULL;

	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = NULL;

	// getting NtQuerySystemInformation address
	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// First NtQuerySystemInformation call
	// This will fail with STATUS_INFO_LENGTH_MISMATCH
	// But it will provide information about how much memory to allocate (uReturnLen1)
	pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	// allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// since we will modify 'SystemProcInfo', we will save its intial value before the while loop to free it later
	pValueToFree = SystemProcInfo;

	// Second NtQuerySystemInformation call
	// Calling NtQuerySystemInformation with the correct arguments, the output will be saved to 'SystemProcInfo'
	STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
		printf("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	while (TRUE) {

		// wprintf(L"[i] Process \"%s\" - Of Pid : %d \n", SystemProcInfo->ImageName.Buffer, SystemProcInfo->UniqueProcessId);

		// Check the process's name size
		// Comparing the enumerated process name to the intended target process
		if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0) {
			// openning a handle to the target process and saving it, then breaking 
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		// if NextEntryOffset is 0, we reached the end of the array
		if (!SystemProcInfo->NextEntryOffset)
			break;

		// moving to the next element in the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	// Free the initial address
	HeapFree(GetProcessHeap(), 0, pValueToFree);

	// Check if we successfully got the target process handle
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}
BOOL GetRemoteProcessHandleSnapshot(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	HANDLE			hSnapShot = NULL;
	PROCESSENTRY32	Proc = {
					.dwSize = sizeof(PROCESSENTRY32)
	};

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {

			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;

			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			// Converting each charachter in Proc.szExeFile to a lowercase character and saving it
			// in LowerName to perform the wcscmp call later

			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		// Compare the enumerated process path with what is passed
		if (wcscmp(LowerName, szProcessName) == 0) {
			// Save the process ID 
			*dwProcessId = Proc.th32ProcessID;
			// Open a process handle and return
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

		// Retrieves information about the next process recorded the snapshot.
		// While we can still have a valid output ftom Process32Next, continue looping
	} while (Process32Next(hSnapShot, &Proc));



_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}

