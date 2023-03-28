#include "ProcessWrapper.h"


typedef NTSTATUS (WINAPI *pZwQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);

pZwQueryInformationProcess ZwQueryInformationProcess = nullptr;

ProcessWrapper::ProcessWrapper(const HANDLE ProcessHandle) {

	ULONG ReturnLength = 0;
	this->processBasicInformation = { 0 };

	if (ProcessHandle == nullptr) {
		return;
	}


	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
	ZwQueryInformationProcess = (pZwQueryInformationProcess)MmGetSystemRoutineAddress(&routineName);

	if (ZwQueryInformationProcess == nullptr)
		return;


	


	HANDLE KProcHandle = nullptr;
	OBJECT_ATTRIBUTES KProcObjectAttributes;
	CLIENT_ID KProcClientId;

	InitializeObjectAttributes(&KProcObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	RtlZeroMemory(&KProcClientId, sizeof(CLIENT_ID));

	KProcClientId.UniqueProcess = ProcessHandle;

	NTSTATUS retStatus = ZwOpenProcess(&KProcHandle, PROCESS_ALL_ACCESS, &KProcObjectAttributes, &KProcClientId);
	if (!NT_SUCCESS(retStatus)) {
		KdPrint(("[WDM NASTYWARE DRIVER]> Failed getting process handle: 0x%X\n", retStatus));
		return;
	}

	retStatus = ZwQueryInformationProcess(KProcHandle, ProcessBasicInformation, &this->processBasicInformation,
												   sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
	if (!NT_SUCCESS(retStatus)) {
		KdPrint(("[WDM NASTYWARE DRIVER]> Error getting process information\n"));
		ZwClose(KProcHandle);
		return;
	}

	ZwClose(KProcHandle);

}

ULONG_PTR ProcessWrapper::get_inherited_from_unique_process_id() const {
	return this->processBasicInformation.InheritedFromUniqueProcessId;
}

ULONG_PTR ProcessWrapper::get_unique_process_id() const {
	return this->processBasicInformation.UniqueProcessId;
}