#include <windows.h>

// PROCESS ENUM ========================================================================== 
BOOL PrintProcesses();
BOOL GetRemoteProcessHandleEnum(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess);
BOOL GetRemoteProcessHandleNt(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess);
BOOL GetRemoteProcessHandleSnapshot(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess);

// PROCESS INJECTION ========================================================================== 
BOOL InjectDllToRemoteProcess(HANDLE hProcess, LPWSTR DllName);
BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress);
BOOL InjectShellcodeToLocalProcess(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress);