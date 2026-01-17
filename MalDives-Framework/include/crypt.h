#pragma once
#include <windows.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

// XOR ---------------------------------------------------------------
VOID XorByOneKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey);
VOID XorByiKeys(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey);
VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize);

// RC4 ---------------------------------------------------------------
VOID Rc4My(IN PBYTE pPayload, IN SIZE_T sPayloadSize, IN PBYTE pKey, IN SIZE_T sKeySize);

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,
	struct USTRING* Key
	);

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize);

// UUID ---------------------------------------------------------------
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);
BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize);

