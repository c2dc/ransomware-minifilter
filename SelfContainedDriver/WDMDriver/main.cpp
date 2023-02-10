#include <ntddk.h>

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1

typedef UINT16 WORD;
typedef UINT32 DWORD;
typedef unsigned char BYTE;
typedef PVOID (*PRtlImageDirectoryEntryToData)(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, PULONG Size);

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;


typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;

	//
	// NT additional fields.
	//

	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
		DWORD   Characteristics;            // 0 for terminating null import descriptor
		DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	} DUMMYUNIONNAME;
	DWORD   TimeDateStamp;                  // 0 if not bound,
											// -1 if bound, and real date\time stamp
											//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
											// O.W. date/time stamp of DLL bound to (Old BIND)

	DWORD   ForwarderChain;                 // -1 if no forwarders
	DWORD   Name;
	DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR, * PIMAGE_IMPORT_DESCRIPTOR;


void DriverUnloadRoutine(PDRIVER_OBJECT);
void CreateProcessHook(PEPROCESS EProcess, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);


extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS retStatus = STATUS_UNSUCCESSFUL;

	KdPrint(("WDM Driver: Loaded\n"));

	// Setting unload routine
	DriverObject->DriverUnload = DriverUnloadRoutine;

	// Set create process notify routine 
	retStatus = PsSetCreateProcessNotifyRoutineEx(CreateProcessHook, FALSE);
	if (NT_SUCCESS(retStatus)) {
		KdPrint(("[WDM Driver Info] : PsSetCreateProcessNotifyRoutineEx Set."));
	}



	return retStatus;
}


void DriverUnloadRoutine(PDRIVER_OBJECT) {
	KdPrint(("WDM Driver: Unloaded.\n"));
	PsSetCreateProcessNotifyRoutineEx(CreateProcessHook, TRUE);
	return;
}

void CreateProcessHook(PEPROCESS EProcess, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo){
	UNREFERENCED_PARAMETER(EProcess);
	if (CreateInfo) {
		UNICODE_STRING FilePath{ 0 };
		UNICODE_STRING RtlImageDirectoryEntryToDataString = RTL_CONSTANT_STRING(L"RtlImageDirectoryEntryToData");	
		NTSTATUS retStatus = STATUS_UNSUCCESSFUL;
		HANDLE FileHandle = NULL;
		OBJECT_ATTRIBUTES ObjectAttr;
		OBJECT_ATTRIBUTES FileObjectAttr;
		IO_STATUS_BLOCK FileStatusBlock{ 0 };
		IO_STATUS_BLOCK File2StatusBlock{ 0 };
		IO_STATUS_BLOCK ReadFileStatusBlock{ 0 };
		FILE_STANDARD_INFORMATION FileInfo{ 0 };
		ULONGLONG FileSize = 0;
		ULONG tableSize = 0;
		PVOID BaseAddress = NULL;
		PRtlImageDirectoryEntryToData RtlImageDirectoryEntryToData = NULL;


		RtlImageDirectoryEntryToData = (PRtlImageDirectoryEntryToData)MmGetSystemRoutineAddress(&RtlImageDirectoryEntryToDataString);
		if (RtlImageDirectoryEntryToData == NULL) {
			return;
		}

		RtlInitUnicodeString(&FilePath, CreateInfo->ImageFileName->Buffer);

		InitializeObjectAttributes(&ObjectAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		InitializeObjectAttributes(&FileObjectAttr, &FilePath, OBJ_KERNEL_HANDLE, NULL, NULL);
	
		
		
		retStatus = ZwOpenFile(&FileHandle, GENERIC_READ, &FileObjectAttr, &FileStatusBlock, FILE_SHARE_READ,
							   FILE_NON_DIRECTORY_FILE);

		if (!NT_SUCCESS(retStatus)) {
			KdPrint(("[WDM Driver Error]> Failed opening file handle to file: %wZ\n", &FilePath));
			return;
		}


		retStatus = ZwQueryInformationFile(FileHandle, &File2StatusBlock, &FileInfo, sizeof(FileInfo), FileStandardInformation);
		if (!NT_SUCCESS(retStatus)) {
			ZwClose(FileHandle);
			KdPrint(("[WDM Driver Error]> Failed querying file information\n"));
			return;
		}

		FileSize = FileInfo.EndOfFile.QuadPart;

		if (FileSize <= 2) {
			ZwClose(FileHandle);
			return;
		}


		BaseAddress = ExAllocatePool2(POOL_FLAG_PAGED, FileSize + 2, 'nskm');

		if (BaseAddress == NULL) {
			KdPrint(("[WDM Driver Error]> Failed to allocate memory for file information\n"));
			ZwClose(FileHandle);
			return;
		}

		LARGE_INTEGER ByteOffset;
		ByteOffset.QuadPart = 0;
		retStatus = ZwReadFile(FileHandle, NULL, NULL, NULL, &ReadFileStatusBlock, BaseAddress, 2, &ByteOffset, NULL);
		if (!NT_SUCCESS(retStatus)) {
			KdPrint(("[WDM Driver Error]> Failed to read first two bytes of data : %X\n", retStatus));
			ZwClose(FileHandle);
			ExFreePool(BaseAddress);
			return;
		}

		if (*((PUINT16)(BaseAddress)) == 0x5a4d) {

			// Then, it is a executable file.
			// Read the rest of the file
			ByteOffset.QuadPart = 0L;
			retStatus = ZwReadFile(FileHandle, NULL, NULL, NULL, &ReadFileStatusBlock, BaseAddress, (ULONG)FileSize, &ByteOffset, NULL);
			if (!NT_SUCCESS(retStatus)) {
				KdPrint(("[WDM Driver Error]> Failed to read file data : %X\n", retStatus));
				ZwClose(FileHandle);
				ExFreePool(BaseAddress);
				return;
			}


			// Try to grap IAT (Import Address Table)
			PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
			PIMAGE_NT_HEADERS32 NtHeaders = (PIMAGE_NT_HEADERS32)((DWORD_PTR)BaseAddress + DosHeader->e_lfanew);
			PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = NULL;
			LPCSTR libName = NULL;

			
			if (NtHeaders->OptionalHeader.Magic == 0x20b || NtHeaders->OptionalHeader.Magic == 0x10b) {
				IMAGE_DATA_DIRECTORY importsDirectory = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
				//ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)BaseAddress);
				ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)RtlImageDirectoryEntryToData(BaseAddress, FALSE,
																IMAGE_DIRECTORY_ENTRY_IMPORT, &tableSize);
				
				if (ImportDescriptor != NULL) {
					libName = (LPCSTR)((DWORD_PTR)ImportDescriptor->Name + (DWORD_PTR)BaseAddress);
					KdPrint(("IMPDName: %wZ\n", libName));
				}

				KdPrint(("Process Information: \nID:%i\nImage File Name: %wZ\nCommand Line: %wZ\nFile Size: %d\nFirst 2 bytes: %x\nNt Header Magic: %X\n",
				HandleToULong(ProcessId), CreateInfo->ImageFileName, CreateInfo->CommandLine, (ULONG)FileSize, DosHeader->e_magic, NtHeaders->OptionalHeader.Magic));
				
				

			}
			

				
			
		}	

		ZwClose(FileHandle);
		ExFreePool(BaseAddress);
	}
}
