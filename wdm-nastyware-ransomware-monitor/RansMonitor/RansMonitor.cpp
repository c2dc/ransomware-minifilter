#include <ntifs.h>
#include "NastywareKernel.h"
#include "RansMonCommon.h"

#define MAX_PROCESS_LIST_SIZE 1024
#define PROCESS_SUSPEND_RESUME 0x0800

typedef LONG(*PsSuspendResumeProcessPtr)(PEPROCESS);

NTSTATUS RansMonitorCreateClose(PDEVICE_OBJECT, PIRP);
NTSTATUS RansMonitorDeviceIoControl(PDEVICE_OBJECT, PIRP);
NTSTATUS RansMonitorRead(PDEVICE_OBJECT, PIRP);

void CreateProcessNotifyRoutine(PEPROCESS, HANDLE, PPS_CREATE_NOTIFY_INFO);
void RansMonitorUnload(PDRIVER_OBJECT);
void Error(const char*, NTSTATUS);
void PushItem(LIST_ENTRY*);

void SuspendProcess(PEPROCESS);
void ResumeProcess(PEPROCESS);

PsSuspendResumeProcessPtr PsSuspendProcess = nullptr;
PsSuspendResumeProcessPtr PsResumeProcess = nullptr;
Globals g_Globals;

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	UNREFERENCED_PARAMETER(RegistryPath);


	g_Globals.Count = 0;
	g_Globals.Mutex.Init();
	g_Globals.ProcessAPI = false;
	InitializeListHead(&g_Globals.listHead);

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT deviceObject = nullptr;
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\RansMonitor");
	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\ransmon");
	bool symbolicLinkCreated = false;


	// Get undocumented functions
	UNICODE_STRING PsSuspendProcessName = RTL_CONSTANT_STRING(L"PsSuspendProcess");
	UNICODE_STRING PsResumeProcessName = RTL_CONSTANT_STRING(L"PsResumeProcess");
	PsSuspendProcess = (PsSuspendResumeProcessPtr)MmGetSystemRoutineAddress(&PsSuspendProcessName);
	PsResumeProcess = (PsSuspendResumeProcessPtr)MmGetSystemRoutineAddress(&PsResumeProcessName);
	if (PsSuspendProcess && PsResumeProcess)
		g_Globals.ProcessAPI = true;


	

	do {

		status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
		if (!NT_SUCCESS(status)) {
			Error("Could not create device object.", status);
			break;
		}

		deviceObject->Flags |= DO_DIRECT_IO;
		status = IoCreateSymbolicLink(&symbolicLink, &deviceName);

		if (!NT_SUCCESS(status)) {
			Error("Could not create symbolic link.", status);
			break;
		}

		symbolicLinkCreated = true;

		
		PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);

	} while (false);

	if (!NT_SUCCESS(status)) {
		if (symbolicLinkCreated) 
			IoDeleteSymbolicLink(&symbolicLink);
		if (deviceObject)
			IoDeleteDevice(deviceObject);
	}

	DriverObject->DriverUnload = RansMonitorUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = RansMonitorCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = RansMonitorRead;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RansMonitorDeviceIoControl;

	return status;
}

NTSTATUS auxCompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG information = 0) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS RansMonitorDeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_NASTYWARE_MON_KILL_PROCESS: {
		if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(NASTYWARE_MON_PROCESS)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PNASTYWARE_MON_PROCESS process = (PNASTYWARE_MON_PROCESS)stack->Parameters.DeviceIoControl.Type3InputBuffer;
		if (process == nullptr) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		OBJECT_ATTRIBUTES oa;
		CLIENT_ID cid;
		HANDLE hProcess;
		cid.UniqueProcess = ULongToHandle(process->processId);
		cid.UniqueThread = 0;

		InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		if (!NT_SUCCESS(status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid))) {
			return auxCompleteIrp(Irp, status);
		}

		if (!NT_SUCCESS(status = ZwTerminateProcess(hProcess, 1))) {
			ZwClose(hProcess);
			return auxCompleteIrp(Irp, status);
		}
		ZwClose(hProcess);
		KdPrint(("Process terminated\n"));
		break;

		

		}
	case IOCTL_NASTYWARE_MON_RESUME_PROCESS: {
		if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(NASTYWARE_MON_PROCESS)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PNASTYWARE_MON_PROCESS process = (PNASTYWARE_MON_PROCESS)stack->Parameters.DeviceIoControl.Type3InputBuffer;
		if (process == nullptr) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}


		HANDLE hProc = nullptr;
		OBJECT_ATTRIBUTES hProcAttr;
		CLIENT_ID hProcCid;
		hProcCid.UniqueProcess = UlongToHandle(process->processId);
		hProcCid.UniqueThread = 0L;
		InitializeObjectAttributes(&hProcAttr, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
		if (!NT_SUCCESS(status = ZwOpenProcess(&hProc, PROCESS_SUSPEND_RESUME, &hProcAttr, &hProcCid))) {
			return auxCompleteIrp(Irp, status);
		}
		PEPROCESS hEProc = nullptr;
		if (!NT_SUCCESS(status = ObReferenceObjectByHandle(hProc, PROCESS_SUSPEND_RESUME, *PsProcessType, KernelMode, (PVOID*)&hEProc, nullptr))) {
			ZwClose(hProc);
			return auxCompleteIrp(Irp, status);
		}

		ResumeProcess(hEProc);


		ObDereferenceObject(hEProc);
		ZwClose(hProc);
	}
	default:
		break;
	}

	return auxCompleteIrp(Irp, status,0);

}

NTSTATUS RansMonitorCreateClose(PDEVICE_OBJECT, PIRP Irp) {
	return auxCompleteIrp(Irp);
}

NTSTATUS RansMonitorRead(PDEVICE_OBJECT , PIRP Irp) {

	if (IsListEmpty(&g_Globals.listHead)) {
		return auxCompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES);
	}

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG length = stack->Parameters.Read.Length;
	ULONG size = sizeof(NASTYWARE_MON_PROCESS);
	NT_ASSERT(Irp->MdlAddress);
	if (length == 0 || length < size) {
		KdPrint(("Buffer too small"));
		return auxCompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL);
	}

	PVOID buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
	if (buffer == nullptr) {
		return auxCompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES);
	}

	NASTYWARE_MON_PROCESS tempProcess;
	g_Globals.Mutex.Lock();
	PNASTYWARE_MON_PROCESS_NODE procNode = CONTAINING_RECORD(RemoveHeadList(&g_Globals.listHead), NASTYWARE_MON_PROCESS_NODE, Entry);
	tempProcess.processId = procNode->ProcessId;
	tempProcess.isRansomware = false;
	ExFreePool(procNode);

	memcpy(buffer, &tempProcess, size);
	g_Globals.Count--;
	g_Globals.Mutex.Unlock();
	KdPrint(("Count : %ul\n", g_Globals.Count));
	return auxCompleteIrp(Irp, STATUS_SUCCESS, size);

}

bool isProcessInLinkedList(ULONG ProcessId) {
	PLIST_ENTRY entry = g_Globals.listHead.Flink;
	while (entry != &g_Globals.listHead) {
		PNASTYWARE_MON_PROCESS_NODE process;
		process = (PNASTYWARE_MON_PROCESS_NODE)CONTAINING_RECORD(entry, NASTYWARE_MON_PROCESS_NODE, Entry);
		if (process->ProcessId == ProcessId)
			return true;

		entry = entry->Flink;
	}
	return false;
}

void CreateProcessNotifyRoutine(PEPROCESS PROC, HANDLE PID, PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(PROC);
	if (CreateInfo) {
		PNASTYWARE_MON_PROCESS_NODE procNode = (PNASTYWARE_MON_PROCESS_NODE)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(NASTYWARE_MON_PROCESS_NODE), 'nskm');
		if (procNode == nullptr) {
			KdPrint(("Could not allocate memory"));
			return;
		}
		procNode->ProcessId = HandleToULong(PID);
		//PushItem(&procNode->Entry);
		KdPrint(("Command: %wZ\n", CreateInfo->CommandLine));
		SuspendProcess(PROC);

	}
}

void Error(const char* message, NTSTATUS status) {
	KdPrint(("RansMonitor : Error : %s 0x%08x\n", message, status));
}

void RansMonitorUnload(PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\ransmon");
	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
	while (!IsListEmpty(&g_Globals.listHead)) {
		PLIST_ENTRY entry = RemoveHeadList(&g_Globals.listHead);
		PNASTYWARE_MON_PROCESS_NODE procNode = CONTAINING_RECORD(entry, NASTYWARE_MON_PROCESS_NODE, Entry);
		ExFreePool(procNode);
	}
	KdPrint(("RansMonitor : Unloaded.\n"));
}

void PushItem(LIST_ENTRY* entry) {
	g_Globals.Mutex.Lock();
	if (g_Globals.Count > MAX_PROCESS_LIST_SIZE) {
		PLIST_ENTRY oldestEntry = RemoveHeadList(&g_Globals.listHead);
		PNASTYWARE_MON_PROCESS_NODE procNode = CONTAINING_RECORD(oldestEntry, NASTYWARE_MON_PROCESS_NODE, Entry);
		ExFreePool(procNode);
		g_Globals.Count--;
	}
	InsertTailList(&g_Globals.listHead, entry);
	g_Globals.Count++;
	g_Globals.Mutex.Unlock();
}

void SuspendProcess(PEPROCESS Process) {
	if (!g_Globals.ProcessAPI)
		return;

	PsSuspendProcess(Process);
}

void ResumeProcess(PEPROCESS Process) {
	if (!g_Globals.ProcessAPI)
		return;

	PsResumeProcess(Process);
}




