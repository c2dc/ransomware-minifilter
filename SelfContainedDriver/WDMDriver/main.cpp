#include <ntddk.h>
#include <minwindef.h>
#include "FunctionEntry.h"

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES      16
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))


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

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

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

typedef struct _IMAGE_NT_HEADERS64 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

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


#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
	BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD   PhysicalAddress;
		DWORD   VirtualSize;
	} Misc;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;


typedef struct _IMAGE_THUNK_DATA64 {
	union {
		ULONGLONG ForwarderString;  // PBYTE 
		ULONGLONG Function;         // PDWORD
		ULONGLONG Ordinal;
		ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
	} u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64* PIMAGE_THUNK_DATA64;

typedef struct _GLOBALS_ {
	FAST_MUTEX FastMutex;
} GLOBALS, *PGLOBALS;


void DriverUnloadRoutine(PDRIVER_OBJECT);
void CreateProcessHook(PEPROCESS EProcess, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);

IMPORT_ENTRY ImportList[1024]{ 0 };
GLOBALS Globals_g{ 0 };

DWORD Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSeh;
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


extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS retStatus = STATUS_UNSUCCESSFUL;
	ExInitializeFastMutex(&Globals_g.FastMutex);

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
	PsSetCreateProcessNotifyRoutineEx(CreateProcessHook, TRUE);
	KdPrint(("WDM Driver: Unloaded.\n"));
	return;
}

void CreateProcessHook(PEPROCESS EProcess, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo){
	UNREFERENCED_PARAMETER(EProcess);
	if (CreateInfo) {

		UNICODE_STRING FilePath{ 0 };
		NTSTATUS retStatus = STATUS_UNSUCCESSFUL;
		HANDLE FileHandle = NULL;
		OBJECT_ATTRIBUTES FileObjectAttr;
		IO_STATUS_BLOCK FileStatusBlock{ 0 };
		IO_STATUS_BLOCK File2StatusBlock{ 0 };
		IO_STATUS_BLOCK ReadFileStatusBlock{ 0 };
		FILE_STANDARD_INFORMATION FileInfo{ 0 };
		ULONGLONG FileSize = 0;
		PVOID BaseAddress = NULL;


		if (CreateInfo->FileOpenNameAvailable == FALSE) {
			return;
		}

		RtlInitUnicodeString(&FilePath, CreateInfo->ImageFileName->Buffer);
		
		KdPrint(("File Name: %wZ\n", FilePath));

		InitializeObjectAttributes(&FileObjectAttr, &FilePath, OBJ_KERNEL_HANDLE, NULL, NULL);
		
		// Try to open a valid handle for the file
		retStatus = ZwCreateFile(&FileHandle, GENERIC_READ, &FileObjectAttr, &FileStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_VALID_FLAGS, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
		if (!NT_SUCCESS(retStatus) || retStatus == INVALID_KERNEL_HANDLE) {
			KdPrint(("[WDM Driver Error]> Failed opening file handle to file: %wZ Code: %X\n", &FilePath, retStatus));
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
		BaseAddress = ExAllocatePool2(POOL_FLAG_PAGED, FileSize + 2, 'nskm');
		if (BaseAddress == NULL) {
			KdPrint(("[WDM Driver Error]> Failed to allocate memory for file information\n"));
			ZwClose(FileHandle);
			return;
		}


		// Read the first two bytes of the file in order to check if it is a executable
		LARGE_INTEGER ByteOffset;
		ByteOffset.QuadPart = 0L;
		retStatus = ZwReadFile(FileHandle, NULL, NULL, NULL, &ReadFileStatusBlock, BaseAddress, 2, &ByteOffset, NULL);
		if (!NT_SUCCESS(retStatus)) {
			KdPrint(("[WDM Driver Error]> Failed to read first two bytes of data : %X\n", retStatus));
			ZwClose(FileHandle);
			ExFreePool(BaseAddress);
			return;
		}

		// CORRECT?


		if (*((PUINT16)(BaseAddress)) == 0x5a4d) {

			// Then, it is a executable file.
			// Read the rest of the file
			memset(&ReadFileStatusBlock, 0, sizeof(ReadFileStatusBlock));
			memset(BaseAddress, 0, FileSize + 2);
			ByteOffset.QuadPart = 0L;
			retStatus = ZwReadFile(FileHandle, NULL, NULL, NULL, &ReadFileStatusBlock, BaseAddress, (ULONG)FileSize, &ByteOffset, NULL);
			if (!NT_SUCCESS(retStatus)) {
				KdPrint(("[WDM Driver Error]> Failed to read file data : %X\n", retStatus));
				ZwClose(FileHandle);
				ExFreePool(BaseAddress);
				return;
			}


			// Try to grap IAT (Import Address Table)

			// Variables used
			PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
			PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)BaseAddress + DosHeader->e_lfanew);
			PIMAGE_SECTION_HEADER pSech = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(NtHeaders);
			PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = NULL;
			DWORD thunk = 0;
			PIMAGE_THUNK_DATA64 thunkData = NULL;
			LPCSTR libName = NULL;
			LPCSTR funcName = NULL;

			


			// Check if the executable is 64 bit
			// If this magic number is zero, then probably something wrong happened
			// TODO: 32 bit version support


			if (NtHeaders->OptionalHeader.Magic == 0x20b) {
				// Lock the list with the mutex
				ExAcquireFastMutex(&Globals_g.FastMutex);



				IMAGE_DATA_DIRECTORY importsDirectory = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
				ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(Rva2Offset(importsDirectory.VirtualAddress, pSech, NtHeaders) + (DWORD_PTR)BaseAddress);


				KdPrint(("Process Information: \nID:%i\nImage File Name: %wZ\nCommand Line: %wZ\nFile Size: %d\nFirst 2 bytes: %x\nNt Header Magic: %X\nImport Descriptor Name: %x\n\n",
					HandleToULong(ProcessId), CreateInfo->ImageFileName, CreateInfo->CommandLine, (ULONG)FileSize, DosHeader->e_magic, NtHeaders->OptionalHeader.Magic, ImportDescriptor->Name));


				while (ImportDescriptor->Name != NULL) {


					// Check if the address is accessible
					if ((Rva2Offset(ImportDescriptor->Name, pSech, NtHeaders) + (DWORD_PTR)BaseAddress) < ((DWORD_PTR)BaseAddress + FileSize) &&
						(Rva2Offset(ImportDescriptor->Name, pSech, NtHeaders)) >= (((DWORD_PTR)BaseAddress + FileSize))) {
						break;
					}
					
					// Grabbing dll name
					libName = (LPCSTR)(Rva2Offset(ImportDescriptor->Name, pSech, NtHeaders) + (DWORD_PTR)BaseAddress);
					KdPrint(("DLL Name: %s\n", libName));

					if ((Rva2Offset(thunk, pSech, NtHeaders) + (DWORD_PTR)BaseAddress) < ((DWORD_PTR)BaseAddress + FileSize) &&
						(Rva2Offset(thunk, pSech, NtHeaders)) >= (((DWORD_PTR)BaseAddress + FileSize))) {
						break;
					}

					// Listing functions fo the dll
					thunk = ImportDescriptor->OriginalFirstThunk == 0 ? ImportDescriptor->FirstThunk : ImportDescriptor->OriginalFirstThunk;
					thunkData = (PIMAGE_THUNK_DATA64)(Rva2Offset(thunk, pSech, NtHeaders) + (DWORD_PTR)BaseAddress);

					
					for (int i = 0; thunkData->u1.AddressOfData != 0; i++) {
						if ((Rva2Offset((DWORD)(thunkData->u1.AddressOfData + 2), pSech, NtHeaders) + (DWORD_PTR)BaseAddress) < ((DWORD_PTR)BaseAddress + FileSize) &&
							(Rva2Offset((DWORD)(thunkData->u1.AddressOfData + 2), pSech, NtHeaders)) >= (((DWORD_PTR)BaseAddress + FileSize))) {
							break;
						}
						funcName = (LPCSTR)(Rva2Offset((DWORD)(thunkData->u1.AddressOfData + 2), pSech, NtHeaders) + (DWORD_PTR)BaseAddress);
						//KdPrint(("\t\tFunction name: %s\n", funcName));

						// Adding to the list
						if (strlen(funcName) > 1 && strlen(libName) > 1) {
							strncpy(ImportList[i].dll_name, libName, 127);
							strncpy(ImportList[i].function_name, funcName, 127);
						}

						thunkData++;
					}
					
					
					ImportDescriptor++;
				}
				
				// Print the whole list
				for (int i = 0; i < 1024 && strlen(ImportList[i].dll_name) > 0 && strlen(ImportList[i].function_name) > 0; i++) {
					KdPrint(("Dll name: %s\tFunction Name:%s\tEntry: %d\n", ImportList[i].dll_name, ImportList[i].function_name, i));
				}

				// Here we will open the imports file and compare the imports



				memset(ImportList, 0, sizeof(ImportList));
				ExReleaseFastMutex(&Globals_g.FastMutex);
			}		
			
		}	

		ZwClose(FileHandle);
		ExFreePool(BaseAddress);
		
	}
}
