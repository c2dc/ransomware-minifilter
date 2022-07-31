#pragma once
#include <string>
#include <yara.h>

struct yaraScanResult {
	bool isRansomware;
};


class YaraRansEngine {
private:
	std::string ruleFileName;
	FILE* ruleFile;
	YR_RULES* yaraRules;
	YR_COMPILER* yaraCompiler;

public:
	YaraRansEngine();
	void setYaraRuleFile(std::string);
	std::string getYaraRuleFile();
	bool YaraScanFile(const std::string);
	~YaraRansEngine();
	void InitializeYara();

};