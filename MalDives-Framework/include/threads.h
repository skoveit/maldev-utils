#pragma once
#include <windows.h>

// thread hijacking
BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize);
BOOL ThreadHijacking(PBYTE pPayload, SIZE_T stPayloadSize, LPCSTR DllName, LPCSTR FunName, DWORD delayMilliseconds);

// CreateProcess 
BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress);

