#pragma once
#include <windows.h>

BOOL InjectDllToRemoteProcess(HANDLE hProcess, LPWSTR DllName);
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode);