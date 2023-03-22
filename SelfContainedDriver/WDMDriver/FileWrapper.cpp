#include "FileWrapper.h"



void FileWrapper::cleanup() {
	if (this->fileHandle != nullptr) {
		ZwClose(this->fileHandle);
		this->fileHandle = nullptr;
	}



}

FileWrapper::FileWrapper(const wchar_t * filePath) {

	// Initialize filePath member

	RtlInitUnicodeString(&this->filePath, filePath);
	this->fileHandle = nullptr;
	this->fileSize = 0;

	


	// Initialize fileObjectAttributes
	OBJECT_ATTRIBUTES fileObjectAttributes;
	RtlZeroMemory(&fileObjectAttributes, sizeof(OBJECT_ATTRIBUTES));
	InitializeObjectAttributes(&fileObjectAttributes, &this->filePath, OBJ_KERNEL_HANDLE, NULL, NULL);

	IO_STATUS_BLOCK fileStatusBlock;
	IO_STATUS_BLOCK fileQueryInfoBlock;
	RtlZeroMemory(&fileStatusBlock, sizeof(IO_STATUS_BLOCK));
	RtlZeroMemory(&fileQueryInfoBlock, sizeof(IO_STATUS_BLOCK));

	FILE_STANDARD_INFORMATION FileStandardInformationData;
	RtlZeroMemory(&FileStandardInformationData, sizeof(FILE_STANDARD_INFORMATION));
	
	NTSTATUS retStatus = ZwCreateFile(&this->fileHandle, GENERIC_READ, &fileObjectAttributes, &fileStatusBlock, NULL,
									  FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (!NT_SUCCESS(retStatus)) {
		KdPrint(("[NASTYWARE WDM DRIVER]> Failed opening file handle: %wZ Code: %X\n", this->filePath, retStatus));
		this->fileHandle = nullptr;
		return;
	}

	retStatus = ZwQueryInformationFile(this->fileHandle, &fileQueryInfoBlock, &FileStandardInformationData, sizeof(FileStandardInformationData), FileStandardInformation);
	if (!NT_SUCCESS(retStatus)) {
		KdPrint(("[NASTYWARE WDM DRIVER]> Failed querying YARA file information\n"));
		this->cleanup();
		return;
	}

	this->fileSize = FileStandardInformationData.EndOfFile.QuadPart;



}

FileWrapper::~FileWrapper() {
	this->cleanup();
}


bool FileWrapper::ReadFileToBuffer(void* destinationBuffer, ULONG destinationBufferSize) {
	if (this->fileHandle == nullptr) {
		KdPrint(("[NASTYWARE WDM DRIVER]> Failed reading file. File handle is null\n"));
		return false;
	}

	if (this->fileSize == 0) {
		KdPrint(("[NASTYWARE WDM DRIVER]> Failed reading file. File size is zero\n"));
		return false;
	}

	if (this->fileSize > destinationBufferSize) {
		KdPrint(("[NASTYWARE WDM DRIVER]> Destination buffer is too small\n"));
		return false;
	}

	LARGE_INTEGER byteOffset;
	IO_STATUS_BLOCK readFileStatusBlock;
	byteOffset.LowPart = byteOffset.HighPart = 0;
	RtlZeroMemory(&readFileStatusBlock, sizeof(IO_STATUS_BLOCK));

	NTSTATUS retStatus = ZwReadFile(this->fileHandle, NULL, NULL, NULL, &readFileStatusBlock,
									destinationBuffer, (ULONG)this->fileSize, &byteOffset, NULL);

	if (!NT_SUCCESS(retStatus)) {
		KdPrint(("[NASTYWARE WDM DRIVER]> Could not read file: %X\n", retStatus));
		return false;
	}

	char* cdestinationBuffer = (char*)destinationBuffer;
	cdestinationBuffer[destinationBufferSize - 1] = '\0';

	return true;


}