#pragma once
#include <windows.h>

// thread hijacking
BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize);
BOOL ThreadHijacking(PBYTE pPayload, SIZE_T stPayloadSize, LPCSTR DllName, LPCSTR FunName, DWORD delayMilliseconds);

// CreateProcess 
BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread);
BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress);

// Loacl
BOOL GetLocalThreadHandle(IN DWORD dwMainThreadId, OUT DWORD* dwThreadId, OUT HANDLE* hThread);