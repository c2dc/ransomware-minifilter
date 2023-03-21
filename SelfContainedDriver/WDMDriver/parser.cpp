#include "Auxiliary.h"

PEParser::PEParser(const int type, const PIMAGE_DOS_HEADER DosHeader, void * BaseAddress, ULONGLONG FileSize, PIMPORT_ENTRY ImportList) {
	this->is32bit = false;
	this->is64bit = false;
	this->DosHeader = DosHeader;
	this->BaseAddress = BaseAddress;
	this->NtHeaders32 = nullptr;
	this->NtHeaders64 = nullptr;
	this->pSech32 = nullptr;
	this->pSech64 = nullptr;
	this->importsDirectory = { 0 };
	this->importDescriptor = nullptr;
	this->ImportList = ImportList;
	this->FileSize = FileSize;

	if (type == 0x10b) {
		this->is32bit = true;
		this->NtHeaders32 = (PIMAGE_NT_HEADERS32)((DWORD_PTR)this->BaseAddress + this->DosHeader->e_lfanew);
		this->pSech32 = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(NtHeaders32);
	}
	else if (type == 0x20b) {
		this->is64bit = true;
		this->NtHeaders64 = (PIMAGE_NT_HEADERS64)((DWORD_PTR)this->BaseAddress + this->DosHeader->e_lfanew);
		this->pSech64 = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(NtHeaders64);
	}

	
}

bool PEParser::check_image_directory_entry() {
	if (is32bit) {
		if (&(NtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]) == NULL) {
			return false;
		}
	}
	else {
		if (&(NtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]) == NULL) {
			return false;
		}
	}

	return true;
}

bool PEParser::set_imports_directory() {
	if (is32bit) {
		this->importsDirectory = NtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		return true;
	}
	else {
		this->importsDirectory = NtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		return true;
	}
}

bool PEParser::set_import_descriptor() {
	if (is32bit) {
		this->importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(this->rva_2_offset(this->importsDirectory.VirtualAddress, pSech32, NtHeaders32) + (DWORD_PTR)this->BaseAddress);
		return true;
	}
	else {
		this->importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(this->rva_2_offset(this->importsDirectory.VirtualAddress, pSech64, NtHeaders64) + (DWORD_PTR)this->BaseAddress);
		return true;
	}
}

bool PEParser::check_rva_address_available(const DWORD rva_address) {
	if ((rva_address + (DWORD_PTR)BaseAddress) < ((DWORD_PTR)this->BaseAddress + this->FileSize) &&
		(rva_address) >= (((DWORD_PTR)this->BaseAddress))) {
		return true;
	}
	return false;
}

bool PEParser::get_function_import_list() {
	DWORD rva_lib_name = 0;
	DWORD rva_thunk_data = 0;
	DWORD thunk = 0;
	PIMAGE_THUNK_DATA64 thunkData = NULL;
	LPCSTR libName = NULL;
	LPCSTR funcName = NULL;
	while (this->importDescriptor->Name != NULL) {
		if (is32bit)
			rva_lib_name = this->rva_2_offset(this->importDescriptor->Name, pSech32, NtHeaders32);
		else
			rva_lib_name = this->rva_2_offset(this->importDescriptor->Name, pSech64, NtHeaders64);
	
		// Check if the address is accessible
		if (!check_rva_address_available(rva_lib_name))
			break;

		// Grabbing dll name
		libName = (LPCSTR)(rva_lib_name + (DWORD_PTR)BaseAddress);

		// Listing functions fo the dll
		thunk = this->importDescriptor->OriginalFirstThunk == 0 ? this->importDescriptor->FirstThunk : this->importDescriptor->OriginalFirstThunk;
		
		if (is32bit)
			rva_thunk_data = this->rva_2_offset(thunk, pSech32, NtHeaders32);
		else
			rva_thunk_data = this->rva_2_offset(thunk, pSech64, NtHeaders64);

		if (!check_rva_address_available(rva_thunk_data))
			break;
		
		thunkData = (PIMAGE_THUNK_DATA64)(rva_thunk_data + (DWORD_PTR)BaseAddress);

		if (thunkData == nullptr) {
			break;
		}

		for (int i = 0; thunkData->u1.AddressOfData != 0 && i < 1024; i++) {

			if (is32bit)
				rva_thunk_data = this->rva_2_offset((DWORD)(thunkData->u1.AddressOfData + 2), pSech32, NtHeaders32);
			else
				rva_thunk_data = this->rva_2_offset((DWORD)(thunkData->u1.AddressOfData + 2), pSech64, NtHeaders64);

			if (!check_rva_address_available(rva_thunk_data))
				break;

			funcName = (LPCSTR)(rva_thunk_data + (DWORD_PTR)BaseAddress);

			// Adding to the list
			if (funcName != nullptr) {
				if (strlen(funcName) > 1 && strlen(libName) > 1) {
					strncpy_s(this->ImportList[i].dll_name, 128, libName, strlen(libName));
					strncpy_s(this->ImportList[i].function_name, 128, funcName, strlen(funcName));
				}
			}

			thunkData++;
		}


		this->importDescriptor++;
	}

	return true;
}


DWORD PEParser::rva_2_offset(DWORD rva, PIMAGE_SECTION_HEADER psh, void* p)
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
