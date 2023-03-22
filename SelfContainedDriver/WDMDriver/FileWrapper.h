#pragma once
#include <ntddk.h>

class FileWrapper {
private:
	ULONGLONG fileSize;
	UNICODE_STRING filePath;
	HANDLE fileHandle;

	void cleanup();
public:
	FileWrapper(const wchar_t * filePath);
	~FileWrapper();
	ULONGLONG getFileSize() const { return this->fileSize; };
	bool ReadFileToBuffer(void* destinationBuffer, ULONG destinationBufferSize);
	void* ReadFile();

};