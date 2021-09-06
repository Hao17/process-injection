#include <windows.h> 
#include <stdio.h> 
#include "tls.h"

#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#else
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#endif

void NTAPI __stdcall TlsCallBack(PVOID DllHandle, DWORD dwReason, PVOID Reserved);

EXTERN_C
#ifdef _WIN64
#pragma const_seg (".CRT$XLB")
const PIMAGE_TLS_CALLBACK _tls_callback = TlsCallBack;
#pragma const_seg ()
#else
#pragma data_seg (".CRT$XLB")
PIMAGE_TLS_CALLBACK _tls_callback = TlsCallBack;
#pragma data_seg ()
#endif

void NTAPI __stdcall TlsCallBack(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
    DWORD dwNumberOfBytesWritten;
    LPCSTR szText = "Unknown\n";
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        szText = "process attach\n";
        break;
    case DLL_PROCESS_DETACH:
        szText = "process detach\n";
        break;
    case DLL_THREAD_ATTACH:
        szText = "thread attach\n";
        break;
    case DLL_THREAD_DETACH:
        szText = "thread detach\n";
        break;
    }
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szText, lstrlenA(szText), &dwNumberOfBytesWritten, 0);
}

#define THREADCOUNT 4 
DWORD dwTlsIndex;

VOID ErrorExit(LPCSTR message);

VOID CommonFunc(VOID)
{
    LPVOID lpvData;

    // Retrieve a data pointer for the current thread. 

    lpvData = TlsGetValue(dwTlsIndex);
    if ((lpvData == 0) && (GetLastError() != ERROR_SUCCESS))
        ErrorExit("TlsGetValue error");

    // Use the data stored for the current thread. 

    printf("common: thread %d: lpvData=%lx\n",
        GetCurrentThreadId(), lpvData);

    Sleep(5000);
}

DWORD WINAPI ThreadFunc(VOID)
{
    LPVOID lpvData;

    // Initialize the TLS index for this thread. 

    lpvData = (LPVOID)LocalAlloc(LPTR, 256);
    if (!TlsSetValue(dwTlsIndex, lpvData))
        ErrorExit("TlsSetValue error");

    printf("thread %d: lpvData=%lx\n", GetCurrentThreadId(), lpvData);

    CommonFunc();

    // Release the dynamic memory before the thread returns. 

    lpvData = TlsGetValue(dwTlsIndex);
    if (lpvData != 0)
        LocalFree((HLOCAL)lpvData);

    return 0;
}

int TlsTest()
{
    DWORD IDThread;
    HANDLE hThread[THREADCOUNT];
    int i;

    // Allocate a TLS index. 

    if ((dwTlsIndex = TlsAlloc()) == TLS_OUT_OF_INDEXES)
        ErrorExit("TlsAlloc failed");

    // Create multiple threads. 

    for (i = 0; i < THREADCOUNT; i++)
    {
        hThread[i] = CreateThread(NULL, // default security attributes 
            0,                           // use default stack size 
            (LPTHREAD_START_ROUTINE)ThreadFunc, // thread function 
            NULL,                    // no thread function argument 
            0,                       // use default creation flags 
            &IDThread);              // returns thread identifier 

      // Check the return value for success. 
        if (hThread[i] == NULL)
            ErrorExit("CreateThread error\n");
    }

    for (i = 0; i < THREADCOUNT; i++)
        WaitForSingleObject(hThread[i], INFINITE);

    TlsFree(dwTlsIndex);

    return 0;
}

VOID ErrorExit(LPCSTR message)
{
    fprintf(stderr, "%s\n", message);
    ExitProcess(0);
}