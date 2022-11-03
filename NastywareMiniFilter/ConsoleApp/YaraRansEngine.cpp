#include "YaraRansEngine.h"
#include <iostream>
#include <stdexcept>
#include <Windows.h>


int nastwareYaraCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
	yaraScanResult* result = (yaraScanResult*)user_data;
	switch (message) {
	case CALLBACK_MSG_RULE_MATCHING:
		result->isRansomware = true;
		return CALLBACK_ABORT;
		break;
	default:
		break;
	}

	return CALLBACK_CONTINUE;
}

YaraRansEngine::YaraRansEngine() {
	yaraCompiler = nullptr;
	yaraRules = nullptr;
	ruleFile = nullptr;
}

void YaraRansEngine::InitializeYara() {
	int result;
	result = yr_initialize();
	if (result != ERROR_SUCCESS) {
		return;
	}

	std::cout << "Yara initialized" << std::endl;

	yaraRules = (YR_RULES*)calloc(1, sizeof(YR_RULES));
	yaraCompiler = (YR_COMPILER*)calloc(1, sizeof(YR_COMPILER));

	if (yaraRules == nullptr || yaraCompiler == nullptr) {
		return;
	}

	result = yr_compiler_create(&yaraCompiler);
	if (result != ERROR_SUCCESS) {
		return;
	}

	std::cout << "Yara compiler created" << std::endl;

	result = fopen_s(&ruleFile, ruleFileName.c_str(), "r");
	if (result != ERROR_SUCCESS) {
		return;
	}

	std::cout << "Yara rule file opened" << std::endl;

	result = yr_compiler_add_file(yaraCompiler, ruleFile, nullptr, ruleFileName.c_str());
	if (result != ERROR_SUCCESS) {
		return;
	}


	result = yr_compiler_get_rules(yaraCompiler, &yaraRules);
	if (result != ERROR_SUCCESS) {
		return;
	}
}

void YaraRansEngine::setYaraRuleFile(std::string ruleFileName) {
	this->ruleFileName = ruleFileName;
}

std::string YaraRansEngine::getYaraRuleFile() {
	return this->ruleFileName;
}

bool YaraRansEngine::YaraScanFile(const std::string fileNameToScan) {
	yaraScanResult yaraResult;
	yaraResult.isRansomware = false;
	int result = 0;

	result = yr_rules_scan_file(yaraRules, fileNameToScan.c_str(), 0, nastwareYaraCallback, &yaraResult, 500000);
	if (result != ERROR_SUCCESS) {
		std::cerr << "Yara failed on scanning file" << std::endl;
		return false;
	}
	if (yaraResult.isRansomware) {
		return true;
	}
	else {
		return false;
	}
}

YaraRansEngine::~YaraRansEngine() {
	yr_rules_destroy(yaraRules);
	yr_compiler_destroy(yaraCompiler);
	yr_finalize();
}