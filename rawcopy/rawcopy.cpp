// rawcopy.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <iostream>
#include <string>
#include <Windows.h>
#include <fstream>

using namespace std;

void ShowHelp() {
	wprintf_s(L"Rawcopy is intended to dump or restore EFS encrypted file.\n\n");
	wprintf_s(L"Usage:\nrawcopy [/f] source destination\nrawcopy /?\n\n");
	wprintf_s(L"Utility checks if source file is EFS encrypted and performs appropriate action.\n");
	wprintf_s(L"If destination already exists, rawcopy fails. Flag /f can be used to overwrite destination.\n\n");
	wprintf_s(L"Rawcopy always interprets last two parameters as source and destination.\n\n");
	wprintf_s(L"Parameters:\n");
	wprintf_s(L"\tSource: file to be dumped or restored. Source file must exist.\n\n");
	wprintf_s(L"\tDestination: file or directory where the source should be copied.\n");
	wprintf_s(L"\tIf destination is a directory, filename of source file will be used.\n\n");
	wprintf_s(L"Flags:\n");
	wprintf_s(L"\t/f\tRawcopy will try to overwrite destination file if it already exists.\n\n");
	wprintf_s(L"\t\t\tWarning! File will be removed before any attempt to open source file!\n\n");
	wprintf_s(L"\t/?\tShow help and exit.\n\n");
	wprintf_s(L"Return values:\n");
	wprintf_s(L"\t0\tCommand completed successfully.\n\n");
	wprintf_s(L"\t1\tParameters count less then two.\n\n");
	wprintf_s(L"\t2\tUnknown flag is set.\n\n");
	wprintf_s(L"\t3\tCouldn't check if source file is encrypted.\n\n");
	wprintf_s(L"\t4\tSource file is a directory.\n\n");
	wprintf_s(L"\t5\tFlag /f set, but couldn't delete destination file.\n\n");
	wprintf_s(L"\t6\tDestination file exists. Use flag /f to override.\n\n");
}

bool AdjustPrivileges(bool IsBackup = true, bool Internal = false) {
	///<summary>Commonly used to store required size for system data.</summary>
	DWORD Size = 0;
	
	///<summary>Shows if required privilege is enabled.</summary>
	bool ReqPrivEnabled = false;
	
	///<summary>Current process token used to adjust privileges.</summary>
	HANDLE hProcToken = NULL;
	
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hProcToken))
	{
		GetTokenInformation(hProcToken, TokenPrivileges, NULL, 0, &Size);
		wprintf_s(L"Size requested: %d\n\n", Size);
		PTOKEN_PRIVILEGES PrivInfo = (PTOKEN_PRIVILEGES)(malloc(Size));
		if (GetTokenInformation(hProcToken, TokenPrivileges, PrivInfo, Size, &Size))
		{
			bool ReqPrivFound = false;
			const wchar_t* ReqPrivName = IsBackup ? SE_BACKUP_NAME : SE_RESTORE_NAME;
			for (size_t i = 0; i < PrivInfo->PrivilegeCount; i++)
			{
				Size = 0;
				LookupPrivilegeName(NULL, &(PrivInfo->Privileges[i].Luid), NULL, &Size);
				LPWSTR Name = new TCHAR[Size];
				LookupPrivilegeName(NULL, &(PrivInfo->Privileges[i].Luid), Name, &Size);
				if (!ReqPrivFound && !wcscmp(Name, ReqPrivName))
				{
					wprintf_s(L"Name: %s\nAttributes: %d\n\n", Name, PrivInfo->Privileges[i].Attributes);
					ReqPrivFound = true;
					ReqPrivEnabled = (bool)(PrivInfo->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED);
					if (ReqPrivEnabled)
					{
						wprintf_s(L"Required privilege is enabled.\n");
					}
					else
					{
						wprintf_s(L"Required privilege is disabled.\n");
						if (!Internal)
						{
							PrivInfo->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;
							Size = 0;
							AdjustTokenPrivileges(hProcToken, false, PrivInfo, 0, NULL, &Size);
							wprintf_s(L"Log size requested: %d\n", Size);
							PTOKEN_PRIVILEGES logPrivInfo = (PTOKEN_PRIVILEGES)(malloc(Size));
							if (ERROR_SUCCESS == AdjustTokenPrivileges(hProcToken, false, PrivInfo, Size, logPrivInfo, &Size))
							{
								wprintf_s(L"Privileges adjusted. Rescanning...\n\n");
								ReqPrivEnabled = AdjustPrivileges(IsBackup, true);
							}
						}
					}
					break;
				}
				wprintf_s(L"1\n");
			}
		}
		else
		{
			fwprintf_s(stderr, L"Couldn't get process token information. Error code: %d", GetLastError());
		}
		CloseHandle(hProcToken);
	}
	else
	{
		fwprintf_s(stderr, L"Couldn't get process token. Error code: %d", GetLastError());
	}
	return ReqPrivEnabled;
}

DWORD WINAPI PfeExportFunc(
	PBYTE pbData,
	PVOID pvCallbackContext,
	ULONG ulLength
)
{
	(reinterpret_cast<fstream*>(pvCallbackContext))->write((char*)pbData, ulLength);
	return ERROR_SUCCESS;
}

int wmain(int argc, wchar_t* argv[])
{	
	if (3 > argc)
	{
		int result = 0;
		if ((argc != 2) || (wcscmp(L"/?", argv[1])))
		{
			fwprintf_s(stderr, L"Error: source or destination not set.\n\n");
			result = 1;
		}
		ShowHelp();
		return result;
	}

	///<summary>If destination is to be overwritten.</summary>
	bool Force = false;

	for (int i = 1; i < argc - 2; i++)
	{
		if (!_wcsicmp(argv[i], L"/f"))
		{
			Force = true;
		}
		else
		{
			fwprintf_s(stderr, L"Unknown flag: %s\n\n", argv[i]);
			ShowHelp();
			return 2;
		}
	}

	wstring SrcFilePath = argv[argc - 2], DstFilePath = argv[argc - 1];

	DWORD SrcFileAttrs;

	if ((SrcFileAttrs = GetFileAttributes(SrcFilePath.c_str())) == INVALID_FILE_ATTRIBUTES)
	{
		fwprintf_s(stderr, L"Couldn't check if source file is encrypted. Error code: %d", GetLastError());
		return 3;
	}
	
	if (SrcFileAttrs & FILE_ATTRIBUTE_DIRECTORY)
	{
		fwprintf_s(stderr, L"Source file is a directory.");
		return 4;
	}

	bool IsBackup = (bool)(SrcFileAttrs & FILE_ATTRIBUTE_ENCRYPTED);

	if (AdjustPrivileges(IsBackup))
	{
		PVOID Context;
		int rescode = 0;

		if (INVALID_FILE_ATTRIBUTES != GetFileAttributes(DstFilePath.c_str()))
		{
			if (Force)
			{
				if (!DeleteFile(DstFilePath.c_str()))
				{
					fwprintf_s(stderr, L"Flag /f set, but couldn't delete destination file. Error code: %d", GetLastError());
					return 5;
				}
			}
			else
			{
				fwprintf_s(stderr, L"Destination file exists. Use flag /f to override.");
				return 6;
			}
		}

		if (IsBackup)
		{
			fstream DstFile(DstFilePath, ios::app | ios::binary);
			rescode = OpenEncryptedFileRaw(SrcFilePath.c_str(), 0, &Context);
			if (!rescode) {
				ReadEncryptedFileRaw(PfeExportFunc, (PVOID)(&DstFile), Context);
				CloseEncryptedFileRaw(Context);
			}
			DstFile.flush();
			DstFile.close();
		}
		return rescode;
	}
	else
	{

	}
	return 0;
}

// Запуск программы: CTRL+F5 или меню "Отладка" > "Запуск без отладки"
// Отладка программы: F5 или меню "Отладка" > "Запустить отладку"

// Советы по началу работы 
//   1. В окне обозревателя решений можно добавлять файлы и управлять ими.
//   2. В окне Team Explorer можно подключиться к системе управления версиями.
//   3. В окне "Выходные данные" можно просматривать выходные данные сборки и другие сообщения.
//   4. В окне "Список ошибок" можно просматривать ошибки.
//   5. Последовательно выберите пункты меню "Проект" > "Добавить новый элемент", чтобы создать файлы кода, или "Проект" > "Добавить существующий элемент", чтобы добавить в проект существующие файлы кода.
//   6. Чтобы снова открыть этот проект позже, выберите пункты меню "Файл" > "Открыть" > "Проект" и выберите SLN-файл.
