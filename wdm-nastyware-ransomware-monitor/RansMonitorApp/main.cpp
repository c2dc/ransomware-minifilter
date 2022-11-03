#include "../RansMonitor/RansMonCommon.h"
#include "YaraRansEngine.h"
#include <iostream>
#include <string>
#include <codecvt>
#include <Psapi.h>

#define MAX_PATH_LENGTH 4096

DWORD GetPID(HANDLE hDevice) {
	NASTYWARE_MON_PROCESS tempProc{0};
	DWORD read{ 0 };
	BOOL success = ReadFile(hDevice, &tempProc, sizeof(NASTYWARE_MON_PROCESS), &read, nullptr);
	if (success == TRUE && read > 0) {
		return tempProc.processId;
	}
	else {
		//std::cerr << "Failed reading device..." << std::endl;
	}
	return 0;
}

bool getProcessImageFileName(DWORD PID, std::wstring &result){
	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, PID);
	if (hProc == nullptr) {
		std::cerr << "Could not get handle for process with PID " << PID << " Error : " << ::GetLastError() << std::endl;
		return false;
	}

	std::wstring processImageName{};
	wchar_t fullPath[MAX_PATH]{0};
	DWORD size = MAX_PATH;
	int ret = GetProcessImageFileName(hProc, fullPath, MAX_PATH);
	if (ret != 0) {
		processImageName.assign(fullPath);
		result = processImageName;
	}
	else {
		std::cerr << "Could not get process info :  " << ::GetLastError() << std::endl;
	}

	return true;
}

// TODO: Search for a better way to convert do driver letter path
void ConvertToDriveLetterPath(std::string& path) {
	std::string result = path;
	size_t pos = result.find_first_of("\\", 1);
	pos = result.find_first_of("\\", pos + 1);
	path.erase(0, pos+1);
	result = "C:\\" + path;
	path = result;
}

void DoWork(HANDLE hDevice) {

	// Mude o PATH do arquivo rules !!
	YaraRansEngine yaraEngine;
	yaraEngine.setYaraRuleFile("C:\\yara_rules\\Ransomware.yar");

	yaraEngine.InitializeYara();

	NASTYWARE_MON_PROCESS tempProcess{0};

	// Maybe change to invert call model using device IOCTLs
	while (true) {
		::Sleep(200);
		DWORD currentProcPid = GetPID(hDevice);
		if (currentProcPid == 0)
			continue;
		std::wstring wcurrentProcImagePath;
		if (!getProcessImageFileName(currentProcPid, wcurrentProcImagePath)) {
			continue;
		}
		

		std::string currentProcImagePath = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(wcurrentProcImagePath);
		ConvertToDriveLetterPath(currentProcImagePath);
		
		if (currentProcImagePath.size() > 0) {
			bool isRansomware = yaraEngine.YaraScanFile(currentProcImagePath);
			tempProcess.processId = currentProcPid;
			if (isRansomware) {
				std::cout << "Ransomware identified in file : " << currentProcImagePath << std::endl;
				tempProcess.isRansomware = true;
				DeviceIoControl(hDevice, IOCTL_NASTYWARE_MON_KILL_PROCESS, &tempProcess, sizeof(NASTYWARE_MON_PROCESS), nullptr, 0, nullptr, nullptr);
			}
			else {
				DeviceIoControl(hDevice, IOCTL_NASTYWARE_MON_RESUME_PROCESS, &tempProcess, sizeof(NASTYWARE_MON_PROCESS), nullptr, 0, nullptr, nullptr);
				std::cout << "File identified as goodware : " << currentProcImagePath << std::endl;
			}
		}

	}

}




int main(int argc, const char* argv[]) {

	HANDLE hDevice = CreateFile(L"\\\\.\\ransmon", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cerr << "Could not open device object" << std::endl;
		return 1;
	}

	DoWork(hDevice);

	CloseHandle(hDevice);
	
	
	return 0;
}