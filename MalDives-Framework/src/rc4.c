#include <stdio.h>
#include <windows.h>
#include <string.h>
#include "../include/crypt.h"

VOID Rc4My(IN PBYTE pPayload, IN SIZE_T sPayloadSize, IN PBYTE pKey, IN SIZE_T sKeySize) {

    unsigned char s[256];
    unsigned char j = 0;
    unsigned char tmp;

    for (int i = 0; i < 256; i++) {
        s[i] = (unsigned char)i;
    }

    for (int i = 0; i < 256; i++) {
        j = (unsigned char)(j + s[i] + pKey[i % sKeySize]);
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }

    unsigned char i = 0;
    j = 0;
    for (size_t n = 0; n < sPayloadSize; n++) {
        i = (unsigned char)(i + 1);
        j = (unsigned char)(j + s[i]);

        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;

        unsigned char k = s[(unsigned char)(s[i] + s[j])];
        pPayload[n] = pPayload[n] ^ k;
    }

    SecureZeroMemory(s, sizeof(s));
}

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

    NTSTATUS	STATUS = NULL;

    USTRING		Key = {
            .Buffer = pRc4Key,
            .Length = dwRc4KeySize,
            .MaximumLength = dwRc4KeySize
    };

    USTRING 	Data = {
            .Buffer = pPayloadData,
            .Length = sPayloadSize,
            .MaximumLength = sPayloadSize
    };

    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    if ((STATUS = SystemFunction032(&Data, &Key)) != 0x0) {
        printf("[!] SystemFunction032 FAILED.Error: 0x%0.8X \n", STATUS);
        return FALSE;
    }

    return TRUE;
}