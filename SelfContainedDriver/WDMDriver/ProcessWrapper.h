#pragma once
#include <ntddk.h>
#include <minwindef.h>
#include <ntstrsafe.h>


class ProcessWrapper {
private:
	PROCESS_BASIC_INFORMATION processBasicInformation;

	
public:
	ProcessWrapper(const HANDLE ProcessHandle);
	ULONG_PTR get_inherited_from_unique_process_id() const;
	ULONG_PTR ProcessWrapper::get_unique_process_id() const;
};