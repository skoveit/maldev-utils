#pragma once
#include <windows.h>

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess);
BOOL InjectDllToRemoteProcess(HANDLE hProcess, LPWSTR DllName);
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode);