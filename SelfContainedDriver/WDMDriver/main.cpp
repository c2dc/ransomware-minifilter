#include <ntddk.h>
#include <minwindef.h>
#include <ntstrsafe.h>
#include "Auxiliary.h"
#include "FunctionEntry.h"
#include "FileWrapper.h"

#define YARA_RULES_PATH L"\\??\\C:\\Users\\hacker\\Desktop\\yara_easy.txt"

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

	do {

		FileWrapper YaraFileObject(YARA_RULES_PATH);
		Globals_g.yara_file_size = YaraFileObject.getFileSize();
		Globals_g.yara_file_data = (char*)ExAllocatePool2(POOL_FLAG_PAGED, YaraFileObject.getFileSize() + 2, 'nskm');
		if (Globals_g.yara_file_data == nullptr) {
			KdPrint(("[WDM Driver Error]> Failed to allocate memory for YARA file information\n"));
			break;
		}

		if (!YaraFileObject.ReadFileToBuffer(Globals_g.yara_file_data, (ULONG)(YaraFileObject.getFileSize() + 2))) {
			retStatus = STATUS_UNSUCCESSFUL;
			break;
		}


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

		PEParser PEFile(CreateInfo->ImageFileName);
		PIMPORT_ENTRY ImportList = PEFile.get_import_list();

		KdPrint(("[+] Checking file: %wZ\n", CreateInfo->ImageFileName));
		bool ret = process_rules(Globals_g.yara_file_data, Globals_g.yara_file_size, ImportList);
		if (ret) {
			KdPrint(("[+] Possible malware: %wZ\n", PEFile.get_file_path()));
		}


	}
}
