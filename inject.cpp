// inject.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#include "tls.h"
#include "inject.h"

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
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		// process hollowing
		char path[MAX_PATH];
		char cmd[] = "notepad.exe";
		char image[] = "helloworld.exe";
		GetModuleFileNameA(0, path, MAX_PATH);

		path[strrchr(path, '\\') - path + 1] = 0;
		strncat_s(path, image, sizeof(image));

		printf("%s\n", path);

		ProcessHollowing(cmd, path);
		LPCSTR szText = "process attach\n";

		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szText, lstrlenA(szText), &dwNumberOfBytesWritten, 0);
		break;
	}
	}

}

int main()
{
    // TlsTest();   
	system("pause"); 
}