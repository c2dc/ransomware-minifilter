#include <ntddk.h>
#include <minwindef.h>
#include <ntstrsafe.h>
#include "Auxiliary.h"
#include "FunctionEntry.h"
#include "FileWrapper.h"

#define YARA_RULES_PATH L"\\??\\C:\\Users\\hacker\\Desktop\\yara_easy.txt"

DWORD Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, void* p);
void DriverUnloadRoutine(PDRIVER_OBJECT);
void CreateProcessHook(PEPROCESS EProcess, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);

GLOBALS Globals_g{ 0 };

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS retStatus = STATUS_SUCCESS;


	// Setting unload routine
	DriverObject->DriverUnload = DriverUnloadRoutine;

	// Open and read yara file
	//HANDLE YaraFileHandle = nullptr;
	//OBJECT_ATTRIBUTES FileObjectAttr;
	//UNICODE_STRING YaraFilePath = RTL_CONSTANT_STRING(YARA_RULES_PATH);
	//IO_STATUS_BLOCK FileStatusBlock{ 0 };
	//IO_STATUS_BLOCK File2StatusBlock{ 0 };
	//IO_STATUS_BLOCK ReadFileStatusBlock{ 0 };
	//FILE_STANDARD_INFORMATION FileInfo{ 0 };
	//ULONGLONG FileSize = 0;

	//RtlZeroMemory(&FileObjectAttr, sizeof(OBJECT_ATTRIBUTES));
	//InitializeObjectAttributes(&FileObjectAttr, &YaraFilePath, OBJ_KERNEL_HANDLE, NULL, NULL);


	do {

		// Try to open a valid handle for the file
		/*
		retStatus = ZwCreateFile(&YaraFileHandle, GENERIC_READ, &FileObjectAttr, &FileStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
		if (!NT_SUCCESS(retStatus)) {
			KdPrint(("[WDM Driver Error]> Failed opening file handle to YARA file: %wZ Code: %X\n", YaraFilePath, retStatus));
			break;
		}
		
		// Query information about file. This way
		// we obtain the size of the file
		retStatus = ZwQueryInformationFile(YaraFileHandle, &File2StatusBlock, &FileInfo, sizeof(FileInfo), FileStandardInformation);
		if (!NT_SUCCESS(retStatus)) {
			KdPrint(("[WDM Driver Error]> Failed querying YARA file information\n"));
			break;
		}

		// Grab file size
		FileSize = FileInfo.EndOfFile.QuadPart;
		Globals_g.yara_file_size = FileSize;

		// File should have DOS HEADER and NT HEADER
		if (FileSize <= (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64))) {
			break;
		}

		// Allocate memory for file content.
		Globals_g.yara_file_data = (char*)ExAllocatePool2(POOL_FLAG_PAGED, FileSize + 2, 'nskm');
		if (Globals_g.yara_file_data == NULL) {
			KdPrint(("[WDM Driver Error]> Failed to allocate memory for YARA file information\n"));
			break;
		}

		// Read the first two bytes of the file in order to check if it is a executable
		LARGE_INTEGER ByteOffset;
		ByteOffset.LowPart = ByteOffset.HighPart = 0;
		retStatus = ZwReadFile(YaraFileHandle, NULL, NULL, NULL, &ReadFileStatusBlock, 
							   Globals_g.yara_file_data, (ULONG)FileSize, &ByteOffset, NULL);
		if (!NT_SUCCESS(retStatus)) {
			KdPrint(("[WDM Driver Error]> Failed to read YARA file: %X\n", retStatus));
			break;
		}

		Globals_g.yara_file_data[FileSize] = '\0';
		ZwClose(YaraFileHandle);
		YaraFileHandle = nullptr;
		*/

		FileWrapper YaraFileObject(YARA_RULES_PATH);
		Globals_g.yara_file_size = YaraFileObject.getFileSize();
		Globals_g.yara_file_data = (char*)ExAllocatePool2(POOL_FLAG_PAGED, YaraFileObject.getFileSize() + 2, 'nskm');
		if (Globals_g.yara_file_data == nullptr) {
			KdPrint(("[WDM Driver Error]> Failed to allocate memory for YARA file information\n"));
			break;
		}

		YaraFileObject.ReadFileToBuffer(Globals_g.yara_file_data, (ULONG)(YaraFileObject.getFileSize() + 2));



		// Set create process notify routine 
		retStatus = PsSetCreateProcessNotifyRoutineEx(CreateProcessHook, FALSE);
		if (NT_SUCCESS(retStatus)) {
			KdPrint(("[WDM Driver Info] : PsSetCreateProcessNotifyRoutineEx Set."));
		}

	} while (false);

	if (!NT_SUCCESS(retStatus)) {
		if (Globals_g.yara_file_data)
			ExFreePool(Globals_g.yara_file_data);
		return retStatus;
	}


	KdPrint(("WDM Driver: Loaded\n"));

	return retStatus;
}


void DriverUnloadRoutine(PDRIVER_OBJECT) {
	PsSetCreateProcessNotifyRoutineEx(CreateProcessHook, TRUE);
	ExFreePool(Globals_g.yara_file_data);
	KdPrint(("WDM Driver: Unloaded.\n"));
	return;
}

void CreateProcessHook(PEPROCESS EProcess, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(EProcess);
	UNREFERENCED_PARAMETER(ProcessId);
	if (CreateInfo) {

		UNICODE_STRING FilePath{ 0 };
		NTSTATUS retStatus = STATUS_UNSUCCESSFUL;
		HANDLE FileHandle = NULL;
		OBJECT_ATTRIBUTES FileObjectAttr{ 0 };
		IO_STATUS_BLOCK FileStatusBlock{ 0 };
		IO_STATUS_BLOCK File2StatusBlock{ 0 };
		IO_STATUS_BLOCK ReadFileStatusBlock{ 0 };
		FILE_STANDARD_INFORMATION FileInfo{ 0 };
		ULONGLONG FileSize = 0;
		char * BaseAddress = NULL;

		RtlZeroMemory(&FileObjectAttr, sizeof(OBJECT_ATTRIBUTES));

		if (CreateInfo->FileOpenNameAvailable == FALSE) {
			return;
		}

		RtlInitUnicodeString(&FilePath, CreateInfo->ImageFileName->Buffer);

		//KdPrint(("PPID: %d\n", CreateInfo->ParentProcessId));
		KdPrint(("\n\nFile Name: %wZ\n", FilePath));

		InitializeObjectAttributes(&FileObjectAttr, &FilePath, OBJ_KERNEL_HANDLE, NULL, NULL);

		// Try to open a valid handle for the file
		retStatus = ZwCreateFile(&FileHandle, GENERIC_READ, &FileObjectAttr, &FileStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_VALID_FLAGS, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
		if (!NT_SUCCESS(retStatus)) {
			KdPrint(("[WDM Driver Error]> Failed opening file handle to file: %wZ Code: %X\n", FilePath, retStatus));
			return;
		}

		// Query information about file. This way
		// we obtain the size of the file
		retStatus = ZwQueryInformationFile(FileHandle, &File2StatusBlock, &FileInfo, sizeof(FileInfo), FileStandardInformation);
		if (!NT_SUCCESS(retStatus)) {
			ZwClose(FileHandle);
			KdPrint(("[WDM Driver Error]> Failed querying file information\n"));
			return;
		}

		// Grab file size
		FileSize = FileInfo.EndOfFile.QuadPart;

		// File should have DOS HEADER and NT HEADER
		if (FileSize <= (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64))) {
			ZwClose(FileHandle);
			return;
		}

		// Allocate memory for file content.
		BaseAddress = (char*)ExAllocatePool2(POOL_FLAG_PAGED, FileSize + 2, 'nskm');
		if (BaseAddress == NULL) {
			KdPrint(("[WDM Driver Error]> Failed to allocate memory for file information\n"));
			ZwClose(FileHandle);
			return;
		}

		// Read the first two bytes of the file in order to check if it is a executable
		LARGE_INTEGER ByteOffset;
		ByteOffset.HighPart = ByteOffset.LowPart = 0;
		retStatus = ZwReadFile(FileHandle, NULL, NULL, NULL, &ReadFileStatusBlock, BaseAddress, 2, &ByteOffset, NULL);
		if (!NT_SUCCESS(retStatus)) {
			KdPrint(("[WDM Driver Error]> Failed to read first two bytes of data : %X\n", retStatus));
			ZwClose(FileHandle);
			ExFreePool(BaseAddress);
			return;
		}

		BaseAddress[FileSize] = '\0';

		KdPrint(("[+] Checking if file is an executable\n"));

		if (BaseAddress[0] == 'M' && BaseAddress[1] == 'Z') {

			// Then, it is an executable file.
			// Read the rest of the file.
			KdPrint(("[+] File is an executable. Reading contents\n"));
			memset(&ReadFileStatusBlock, 0, sizeof(ReadFileStatusBlock));
			memset(BaseAddress, 0, FileSize + 2);
			ByteOffset.LowPart = ByteOffset.HighPart = 0;
			retStatus = ZwReadFile(FileHandle, NULL, NULL, NULL, &ReadFileStatusBlock, BaseAddress, (ULONG)FileSize, &ByteOffset, NULL);
			if (!NT_SUCCESS(retStatus)) {
				KdPrint(("[WDM Driver Error]> Failed to read file data : %X\n", retStatus));
				ZwClose(FileHandle);
				ExFreePool(BaseAddress);
				return;
			}
			BaseAddress[FileSize] = '\0';

			KdPrint(("[+] All file data mapped\n"));


			// Try to grap IAT (Import Address Table)
			
			// Variables used
			PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
			PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)BaseAddress + DosHeader->e_lfanew);
			if (NtHeaders == NULL) {
				KdPrint(("[WDM Driver Error]> Failed accessing ntheaders\n"));
				ZwClose(FileHandle);
				ExFreePool(BaseAddress);
				return;
			}

			PIMAGE_SECTION_HEADER pSech = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(NtHeaders);
			if (pSech == NULL) {
				KdPrint(("[WDM Driver Error]> Failed accessing ntheaders\n"));
				ZwClose(FileHandle);
				ExFreePool(BaseAddress);
				return;
			}

			//PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = NULL;
			//DWORD thunk = 0;
			//PIMAGE_THUNK_DATA64 thunkData = NULL;
			//LPCSTR libName = NULL;
			//LPCSTR funcName = NULL;
			
			PIMPORT_ENTRY ImportList = nullptr;
			

			// Check if the executable is 64 bit
			// If this magic number is zero, then probably something wrong happened
			// TODO: 32 bit version support

			KdPrint(("[+] Creating import list\n"));
			ImportList = (PIMPORT_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(IMPORT_ENTRY) * 1024, 'nskm');
			if (ImportList == nullptr) {
				ZwClose(FileHandle);
				ExFreePool(BaseAddress);
				return;
			}

			

			PEParser PeInfo(NtHeaders->OptionalHeader.Magic, DosHeader, BaseAddress, FileSize, ImportList);
			

			KdPrint(("[+] Checking the imports against the rules\n"));
			bool ret = process_rules(Globals_g.yara_file_data, Globals_g.yara_file_size, ImportList);
			if (ret) {
				KdPrint(("[+] Possible malware: %wZ\n", FilePath));
			}

			ExFreePool(ImportList);

		}

		ZwClose(FileHandle);
		ExFreePool(BaseAddress);
		KdPrint(("[+] Done.\n\n"));

	}
}


DWORD Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, void* p)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSeh;
	PIMAGE_NT_HEADERS pnt = (PIMAGE_NT_HEADERS)p;
	if (rva == 0)
	{
		return (rva);
	}
	pSeh = psh;
	for (i = 0; i < pnt->FileHeader.NumberOfSections; i++)
	{
		if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
			pSeh->Misc.VirtualSize)
		{
			break;
		}
		pSeh++;
	}
	return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}