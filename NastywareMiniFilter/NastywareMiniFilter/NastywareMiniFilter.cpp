#include <fltKernel.h>
#include <dontuse.h>
#include "Common.h"


typedef struct _GLOBALS_ {
	PFLT_FILTER Filter;
	PFLT_PORT ClientPort;
	PFLT_PORT ServerPort;
} GLOBALS, * PGLOBALS;


extern "C"
NTSTATUS ZwQueryInformationProcess(
	HANDLE hProcess,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);

GLOBALS Globals;

NTSTATUS DriverUnload(FLT_FILTER_UNLOAD_FLAGS);
//FLT_PREOP_CALLBACK_STATUS NastywarePreCreateCallback(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
NTSTATUS PortConnectNotify(PFLT_PORT, PVOID, PVOID, ULONG, PVOID*);
void PortDisconnectNotify(PVOID ConnectionCookie);
void NastywareCreateProcessNotify(PEPROCESS, HANDLE, PPS_CREATE_NOTIFY_INFO);
NTSTATUS PortMessageNotify(PVOID, PVOID, ULONG, PVOID, ULONG, PULONG);

const FLT_OPERATION_REGISTRATION  FilterOperations[] = {
	//{IRP_MJ_CREATE, 0, NastywarePreCreateCallback, nullptr},
	{IRP_MJ_OPERATION_END}
};

const FLT_REGISTRATION FilterRegistration = {
		sizeof(FLT_REGISTRATION),	// Size
		FLT_REGISTRATION_VERSION,	// Version
		0L,							// Flags
		NULL,						// Context

		FilterOperations,			// Array of supported operations
		DriverUnload,				// Unload function
		NULL,						// InstanceSetupCallback
		NULL,						// Detach

		NULL,						// InstanceTeardownStartCallback
		NULL,						// InstanceTeardownCompleteCallback
		NULL,
		NULL,

		NULL,
		NULL,
		NULL,
		NULL,
		
};

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS retStatus = STATUS_UNSUCCESSFUL;

	do {
		PSECURITY_DESCRIPTOR sd;
		retStatus = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
		UNICODE_STRING CommunicationPortName = RTL_CONSTANT_STRING(L"\\NastyPort");
		OBJECT_ATTRIBUTES ObjAttr;
		InitializeObjectAttributes(&ObjAttr, &CommunicationPortName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, sd);
		

		retStatus = FltRegisterFilter(DriverObject, &FilterRegistration, &Globals.Filter);

		if (!NT_SUCCESS(retStatus)) {
			KdPrint((DRIVER_PREFIX "Failed registering filter\n"));
			break;
		}
		KdPrint((DRIVER_PREFIX "Filter Registered\n"));

		retStatus = FltCreateCommunicationPort(Globals.Filter, &Globals.ServerPort, &ObjAttr, nullptr, PortConnectNotify, PortDisconnectNotify, PortMessageNotify, 1);
		FltFreeSecurityDescriptor(sd);
		if (!NT_SUCCESS(retStatus)) {
			KdPrint((DRIVER_PREFIX "Failed creating communication port\n"));
			break;
		}

		if (NT_SUCCESS(retStatus)) {
			KdPrint((DRIVER_PREFIX "Driver registered successfully\n"));
			retStatus = FltStartFiltering(Globals.Filter);
			if (!NT_SUCCESS(retStatus)) {
				KdPrint((DRIVER_PREFIX "Could not start filtering\n"));
				FltUnregisterFilter(Globals.Filter);
			}
		}

		retStatus = PsSetCreateProcessNotifyRoutineEx(NastywareCreateProcessNotify, FALSE);
		if (!NT_SUCCESS(retStatus)) {
			PsSetCreateProcessNotifyRoutineEx(NastywareCreateProcessNotify, TRUE);
			break;
		}
		KdPrint((DRIVER_PREFIX "Process hooking enabled\n"));
	} while(FALSE);


	KdPrint((DRIVER_PREFIX "Driver loaded\n")); 

	return retStatus;

}

NTSTATUS DriverUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
	UNREFERENCED_PARAMETER(Flags);
	PsSetCreateProcessNotifyRoutineEx(NastywareCreateProcessNotify, TRUE);
	FltCloseCommunicationPort(Globals.ServerPort);
	FltUnregisterFilter(Globals.Filter);
	KdPrint((DRIVER_PREFIX "Driver unloaded\n"));
	return STATUS_SUCCESS;
}

NTSTATUS PortConnectNotify(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID*ConnectionPortCookie) {
	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionPortCookie);

	Globals.ClientPort = ClientPort;


	return STATUS_SUCCESS;
}

void PortDisconnectNotify(PVOID ConnectionCookie) {
	UNREFERENCED_PARAMETER(ConnectionCookie);

	FltCloseClientPort(Globals.Filter, &Globals.ClientPort);
	Globals.ClientPort = nullptr;

	KdPrint((DRIVER_PREFIX "Client disconnected from port"));

}

NTSTATUS PortMessageNotify(
	IN PVOID PortCookie,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnOutputBufferLength
){
	UNREFERENCED_PARAMETER(PortCookie);
	UNREFERENCED_PARAMETER(InputBuffer);
	UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(ReturnOutputBufferLength);
	return STATUS_SUCCESS;
}




void NastywareCreateProcessNotify(PEPROCESS Eprocess, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO Create) {
	// If process is beign created
	UNREFERENCED_PARAMETER(Eprocess);
	if (Create) {
		// We will use ProcessImageFileName so we need UNICODE_STRING structure
		ULONG FilePathLength = 0L;
		NTSTATUS retStatus = 0L;
		PUNICODE_STRING FileImagePath = nullptr;
		PNASTYWARE_MESSAGE Message = nullptr;
		NASTYWARE_FEEDBACK UserModeReply;
		ULONG ReplyLength = sizeof(NASTYWARE_FEEDBACK); // ?
		ULONG length = sizeof(NASTYWARE_MESSAGE);
		do {

			FilePathLength = sizeof(UNICODE_STRING) + 1024;
			retStatus;
			FileImagePath = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_PAGED, FilePathLength, 'nskm');
			if (FileImagePath == nullptr) {
				break;
			}


			// NASTYAWARE_MESSAGE SETUP
			Message = (PNASTYWARE_MESSAGE)ExAllocatePool2(POOL_FLAG_PAGED, length, 'nskm');
			if (Message == nullptr) {
				break;
			}

			// Getting a handle to the process because although ProcessId has a type HANDLE it is just the process ID
			HANDLE hProcess;
			OBJECT_ATTRIBUTES oa;
			CLIENT_ID cid;
			InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
			cid.UniqueProcess = ProcessId;
			cid.UniqueThread = 0L;

			// Try to get the process handle
			if (!NT_SUCCESS(retStatus = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid))) {
				KdPrint((DRIVER_PREFIX "Failed getting process handle\n"));
			}
			else {
				RtlZeroMemory(Message, length);
				RtlZeroMemory(FileImagePath, FilePathLength);
				RtlZeroMemory(&UserModeReply, ReplyLength);

				// Get process image file name
				retStatus = ZwQueryInformationProcess(hProcess, ProcessImageFileName, FileImagePath, FilePathLength, nullptr);
				if (!NT_SUCCESS(retStatus)) {
					KdPrint((DRIVER_PREFIX "Failed getting process information : 0x%x Required size:\n", retStatus));
				}
				else {
					//KdPrint((DRIVER_PREFIX "Process Image Name 1: %ws\n", FileImagePath->Buffer));
				}
				ZwClose(hProcess);

				// Initialize Message
				RtlCopyMemory(Message->FileName, FileImagePath->Buffer, FileImagePath->Length);
				Message->Length = FileImagePath->Length;
				UserModeReply.Malware = FALSE;

				// Sending message to user mode and wait for reply
				retStatus = FltSendMessage(Globals.Filter, &Globals.ClientPort, Message, length, &UserModeReply, &ReplyLength, NULL);
				
				// If the process is identified as malware, stop its creation
				// TODO???: ZwTerminateProcess necessary?
				if (!NT_SUCCESS(retStatus) || retStatus == STATUS_TIMEOUT) {
					KdPrint(("Some error or timetou\n"));
					break;
				}

				if (UserModeReply.Malware) {
					KdPrint(("Malware: %ws\n", FileImagePath->Buffer));
					Create->CreationStatus = STATUS_UNSUCCESSFUL;
				}
				else {
					KdPrint(("Legitimate: %ws\n", FileImagePath->Buffer));
				}
			}
		} while (false);
		if (Message != nullptr)
			ExFreePool(Message);
		if (FileImagePath != nullptr)
			ExFreePool(FileImagePath);
	} 
}
