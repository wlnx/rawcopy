#include <iostream>
#include <Windows.h>
#include <strsafe.h>
#include <Shlwapi.h>
#include <PathCch.h>

using namespace std;

LPCWSTR ErrMsgs[] = {
	L"Operation completed successfully",
	L"Failed to write dump",
	L"Failed to read dump",
	L"Invalid parameter count",
	L"Invalid argument",
	L"Source is a directory",
	L"Cannot check source (maybe, not exist or inaccessible)",
	L"Source parse error",
	L"Destination parse error",
	L"Failed to create destination file name from directory (try to specify full destination file name)",
	L"Destination file exists (use /f to override)",
	L"Failed to create destination file to dump data",
	L"Failed to open encrypted file to dump from (elevation needed?)",
	L"Failed to dump encrypted file (elevation needed?)",
	L"Failed to open dump file to restore from",
	L"Failed to create file to import dump to (elevation needed?)",
	L"Failed to restore encrypted file (elevation needed?)",
	L""
};

void ShowHelp()
{
	wprintf_s(
		L"%s%s%s%s%s%s%s%s%s",
		L"Utility to dump or restore EFS-encrypted files.\n",
		L"If source file is EFS-encrypted, it will be dumped to destination.\n",
		L"If source file is not EFS-encrypted, it is considered to be a dump and utility will restore it to destination.\n\n",
		L"Usage:\n\trawcopy [/f] source destination\nrawcopy /?\n\n",
		L"Parameters:\n",
		L"\t/f\t\tIf destination file exists it will be overwritten.\n",
		L"\tsource\t\tFile to be dumped or restored from. File must exist. If source is a directory, operation fails. Wildcards are not accepted.\n",
		L"\tdestination\tFile to be dumped or restored to. If destination is a directory, filename of source preserved.\n\n",
		L"Return codes:\n\t0\tOperation completed successfully\n"
	);
	int i = 3;
	while (!lstrcmp(L"", ErrMsgs[i]))
	{
		wprintf_s(L"\t%d\t%s\n", i, ErrMsgs[i]);
	}
}

void PrintErrMsg(
	DWORD errcode
)
{
	LPWSTR SysMsg = NULL;
	if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, errcode, LANG_USER_DEFAULT, SysMsg, 0, NULL))
	{
		fwprintf_s(stderr, L"%s\n\n", SysMsg);
		LocalFree(SysMsg);
	}
}

DWORD WINAPI PfeExportFunc(
	PBYTE pbData,
	PVOID pvCallbackContext,
	ULONG ulLength
)
{
	if (WriteFile(*(PHANDLE)pvCallbackContext, pbData, ulLength, &ulLength, NULL))
	{
		return ERROR_SUCCESS;
	}
	else
	{
		DWORD errcode = GetLastError();
		fwprintf_s(stderr, L"Error: %s. Error code: %d\n\n", ErrMsgs[1], errcode);
		PrintErrMsg(errcode);
		return errcode;
	}
}

DWORD WINAPI PfeImportFunc(
	PBYTE pbData,
	PVOID pvCallbackContext,
	PULONG ulLength
)
{
	if (ReadFile(*(PHANDLE)pvCallbackContext, pbData, *ulLength, ulLength, NULL))
	{
		return ERROR_SUCCESS;
	}
	else
	{
		DWORD errcode = GetLastError();
		fwprintf_s(stderr, L"Error: %s. Error code: %d\n\n", ErrMsgs[2], errcode);
		PrintErrMsg(errcode);
		return errcode;
	}
}

int wmain(int argc, wchar_t* argv[])
{	
	///<summary>Encrypted file pointer</summary>
	PVOID file_enc = NULL;

	///<summary>Raw file pointer</summary>
	HANDLE file_raw = NULL;

	// Formal cmdline args validation

	// Wrong param count
	if (argc < 2 || argc > 4)
	{
		fwprintf_s(stderr, L"Error: %s: %d\n\n", ErrMsgs[3], argc);
		ShowHelp();
		return 3;
	}

	// Wrong parameters
	else if (((argc == 2) && lstrcmp(L"/?", argv[1])) || ((argc == 4) && lstrcmpi(L"/f", argv[1])))
	{
		fwprintf_s(stderr, L"Error: %s: %s\n\n", ErrMsgs[4], argv[1]);
		ShowHelp();
		return 4;
	}

	// Show help
	else if (argc == 2)
	{
		ShowHelp();
		return 0;
	}

	// Formal cmdlime args validated

	// Source validation

	DWORD SrcAttrs = GetFileAttributes(argv[argc - 2]);

	// Check if source is accessible
	if (INVALID_FILE_ATTRIBUTES == SrcAttrs)
	{
		fwprintf_s(stderr, L"Error: %s: \"%s\"\n\n", ErrMsgs[6], argv[argc - 2]);
		return 6;
	}
	
	// Check if source is a directory
	else if (SrcAttrs & FILE_ATTRIBUTE_DIRECTORY)
	{
		fwprintf_s(stderr, L"Error: %s: \"%s\"\n\n", ErrMsgs[5], argv[argc - 2]);
		return 5;
	}

	// Source validated

	// Destination validation

	DWORD DstAttrs = GetFileAttributes(argv[argc - 1]);

	// Check if destination is a directory
	if ((INVALID_FILE_ATTRIBUTES != DstAttrs) && (DstAttrs & FILE_ATTRIBUTE_DIRECTORY))
	{
			
		// Get file name from source
		size_t SrcSize = 0;
		if (S_OK != StringCchLength(argv[argc - 2], STRSAFE_MAX_CCH, &SrcSize))
		{
			fwprintf_s(stderr, L"Error: %s: \"%s\"\n\n", ErrMsgs[7], argv[argc - 2]);
			return 7;
		}
		SrcSize++;
		LPWSTR SrcFileName = (LPWSTR) malloc(sizeof(wchar_t) * SrcSize);
		StringCchCopy(SrcFileName, SrcSize, argv[argc - 2]); // Hope there will be no errors here (:
		PathStripPath(SrcFileName);
		if (S_OK != StringCchLength(SrcFileName, STRSAFE_MAX_CCH, &SrcSize))
		{
			fwprintf_s(stderr, L"Error: %s: \"%s\"\n\n", ErrMsgs[7], SrcFileName);
			return 7;
		}
		// File name from source extracted

		// Create full destination name
		size_t DstSize = 0;
		if (S_OK != StringCchLength(argv[argc - 1], STRSAFE_MAX_CCH, &DstSize))
		{
			fwprintf_s(stderr, L"Error: %s: \"%s\"\n\n", ErrMsgs[8], argv[argc - 1]);
			return 8;
		}
		DstSize += SrcSize + 2; // Trailing \0 and possible path separator added to size
		LPWSTR DstFileName = (LPWSTR)malloc(sizeof(wchar_t) * DstSize);
		StringCchCopy(DstFileName, DstSize, argv[argc - 1]); // Hope there will be no errors here (:
		if (S_OK != PathCchAppend(DstFileName, DstSize, SrcFileName))
		{
			fwprintf_s(stderr, L"Error: %s.\nSource: \"%s\"\nExtracted file name: \"%s\"\nDestination: \"%s\"\n\n", ErrMsgs[9], argv[argc - 2], SrcFileName, argv[argc - 1]);
			return 9;
		}
		// Full destination name created

		// Replace destination directory with full file name
		argv[argc - 1] = DstFileName;

		// Update DstAttrs
		DstAttrs = GetFileAttributes(argv[argc - 1]);
	}
	
	if ((INVALID_FILE_ATTRIBUTES != DstAttrs) && (3 == argc))
	{
		fwprintf_s(stderr, L"Error: %s: \"%s\"\n\n", ErrMsgs[10], argv[argc - 1]);
		return 10;
	}

	// Destination validated

	int retcode = 0;

	if (SrcAttrs & FILE_ATTRIBUTE_ENCRYPTED)
	{
		// Dump operation

		if (INVALID_HANDLE_VALUE != (file_raw = CreateFile2(argv[argc - 1], FILE_APPEND_DATA, 0, (4 == argc) ? CREATE_ALWAYS : CREATE_NEW, NULL)))
		{
			if (GetLastError() == ERROR_ALREADY_EXISTS)
			{
				wprintf_s(L"Destination file overwritten: \"%s\"\n\n", argv[argc - 1]);
			}
		}
		else
		{
			fwprintf_s(stderr, L"Error: %s: \"%s\"\n\n", ErrMsgs[11], argv[argc - 1]);
			PrintErrMsg(GetLastError());
			return 11;
		}
		
		if (ERROR_SUCCESS != OpenEncryptedFileRaw(argv[argc - 2], 0, &file_enc))
		{
			fwprintf_s(stderr, L"Error: %s: \"%s\"\n\n", ErrMsgs[12], argv[argc - 2]);
			PrintErrMsg(GetLastError());
			retcode = 12;
		}
		else
		{
			if (ERROR_SUCCESS != ReadEncryptedFileRaw(PfeExportFunc, &file_raw, file_enc))
			{
				fwprintf_s(stderr, L"Error: %s: \"%s\"\n\n", ErrMsgs[13], argv[argc - 2]);
				PrintErrMsg(GetLastError());
				retcode = 13;
			}
			CloseEncryptedFileRaw(file_enc);
		}
		CloseHandle(file_raw);
	}
	else
	{
		// Restore operation

		if (INVALID_HANDLE_VALUE == (file_raw = CreateFile2(argv[argc - 2], FILE_READ_ACCESS, FILE_SHARE_READ, OPEN_EXISTING, NULL)))
		{
			fwprintf_s(stderr, L"Error: %s: \"%s\"\n\n", ErrMsgs[14], argv[argc - 2]);
			PrintErrMsg(GetLastError());
			return 14;
		}
		if (ERROR_SUCCESS != OpenEncryptedFileRaw(argv[argc - 1], CREATE_FOR_IMPORT, &file_enc))
		{
			fwprintf_s(stderr, L"Error: %s: \"%s\"\n\n", ErrMsgs[15], argv[argc - 1]);
			PrintErrMsg(GetLastError());
			retcode = 15;
		}
		else
		{
			if (ERROR_SUCCESS != WriteEncryptedFileRaw(PfeImportFunc, &file_raw, file_enc))
			{
				fwprintf_s(stderr, L"Error: %s: \"%s\"\n\n", ErrMsgs[16], argv[argc - 1]);
				PrintErrMsg(GetLastError());
				retcode = 16;
			}
			CloseEncryptedFileRaw(file_enc);
		}
		CloseHandle(file_raw);
	}
	return retcode;
}
