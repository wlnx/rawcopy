// rawcopy.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <iostream>
#include <string>
#include <Windows.h>
#include <fstream>

using namespace std;

DWORD WINAPI PfeExportFunc(
	PBYTE pbData,
	PVOID pvCallbackContext,
	ULONG ulLength
)
{
	WriteFile(*(PHANDLE)pvCallbackContext, pbData, ulLength, &ulLength, NULL);
	return ERROR_SUCCESS;
}

DWORD WINAPI PfeImportFunc(
	PBYTE pbData,
	PVOID pvCallbackContext,
	PULONG ulLength
)
{
	ReadFile(*(PHANDLE)pvCallbackContext, pbData, *ulLength, ulLength, NULL);
	return ERROR_SUCCESS;
}

int wmain(int argc, wchar_t* argv[])
{	
	PVOID file_enc = NULL;
	HANDLE file_raw = NULL;
	
	if (GetFileAttributes(argv[argc - 2]) & FILE_ATTRIBUTE_ENCRYPTED)
	{
		// Dump operation

		file_raw = CreateFile2(argv[argc - 1], FILE_APPEND_DATA, 0, CREATE_ALWAYS, NULL);
		OpenEncryptedFileRaw(argv[argc - 2], 0, &file_enc);
		ReadEncryptedFileRaw(PfeExportFunc, &file_raw, file_enc);
		CloseEncryptedFileRaw(file_enc);
		CloseHandle(file_raw);
	}
	else
	{
		// Restore operation

		file_raw = CreateFile2(argv[argc - 2], FILE_READ_ACCESS, FILE_SHARE_READ, OPEN_EXISTING, NULL);
		OpenEncryptedFileRaw(argv[argc - 1], CREATE_FOR_IMPORT, &file_enc);
		WriteEncryptedFileRaw(PfeImportFunc, &file_raw, file_enc);
		CloseEncryptedFileRaw(file_enc);
		CloseHandle(file_raw);
	}
	return 0;
}
