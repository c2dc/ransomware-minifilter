#include <iostream>
#include <string>
#include <codecvt>
#include <Windows.h>
#include <fltUser.h>
#include <SubAuth.h>

#include "../NastywareMiniFilter/Common.h"
#include "YaraRansEngine.h"
#pragma comment(lib, "fltlib")

HANDLE hPort;


bool replace(std::wstring& string1, const std::wstring& string2, const std::wstring& string3) {
	size_t begin = string1.find(string2);
	if (begin == std::string::npos)
		return false;

	string1.replace(begin, string2.length(), string3);
	return true;
}

void display_reply(const NASTYWARE_REPLY_MESSAGE& reply, const std::wstring & filename) {
	std::wcout << std::endl <<  "[ REPLY ]" << std::endl << "MessageId\t:\t" << reply.ReplyHeader.MessageId << std::endl;
	std::wcout << "Status\t:\t" << reply.ReplyHeader.Status << std::endl;
	std::wcout << "Malware\t:\t" << std::boolalpha << reply.Feedback.Malware << std::endl;
	std::wcout << "Filename\t:\t" << filename << std::endl;
	std::wcout << "[ END OF REPLY ]" << std::endl << std::endl;
}

void HandleMessage(const BYTE* buffer, ULONGLONG MessageId, YaraRansEngine & ScanEngine) {
	PNASTYWARE_MESSAGE message = (PNASTYWARE_MESSAGE)buffer;
	NASTYWARE_REPLY_MESSAGE ReplyMessage;
	HRESULT hr;
	ULONG ReplyBufferLength = sizeof(FILTER_REPLY_HEADER) + sizeof(NASTYWARE_FEEDBACK);
	std::wstring filepath(message->FileName, message->Length);
	replace(filepath, L"\\Device\\", L"\\\\?\\");

	std::string utf8_filepath = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().to_bytes(filepath);
	filepath.erase(std::remove(filepath.begin(), filepath.end(), '\n'), filepath.end());


	ReplyMessage.ReplyHeader.MessageId = MessageId;
	ReplyMessage.ReplyHeader.Status = STATUS_SUCCESS;
	ReplyMessage.Feedback.Malware = FALSE;

	if (ScanEngine.YaraScanFile(utf8_filepath)) {
		ReplyMessage.Feedback.Malware = TRUE;
	}
	

	display_reply(ReplyMessage, filepath);
	
	hr = FilterReplyMessage(hPort, &ReplyMessage.ReplyHeader, ReplyBufferLength);
	if (FAILED(hr)) {
		std::wcout << "Failed replying to kernel mode : " << std::hex << hr << std::endl;
	}
	else if (hr != S_OK) {
		std::wcerr << "Some error ocurred :" << std::hex << hr << std::endl;
	}
}

int main(int argc, char* argv[]) {

	
	HRESULT hr = FilterConnectCommunicationPort(L"\\NastyPort", 0, nullptr, 0, nullptr, &hPort);
	YaraRansEngine Yara;
	
	if (FAILED(hr)) {
		std::cerr << "[-] Error while connecting to mini-filter port. Is the driver active?" << std::endl;
		return 1;
	}

	Yara.setYaraRuleFile("./yara-4.2.2/Blackcat.yar");
	Yara.InitializeYara();

	BYTE buffer[1 << 16];
	PFILTER_MESSAGE_HEADER message = (PFILTER_MESSAGE_HEADER)buffer;

	// Receive messages from the driver forever
	for (;;) {
		hr = FilterGetMessage(hPort, message, sizeof(buffer), nullptr);
		if (FAILED(hr)) {
			std::cerr << "[-] Error receiving message :" << std::hex << hr << std::endl;
			break;
		}
		HandleMessage(buffer + sizeof(FILTER_MESSAGE_HEADER), message->MessageId, Yara);
	}


	return 0;
}
