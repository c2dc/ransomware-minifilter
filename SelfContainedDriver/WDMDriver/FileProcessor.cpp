#include <ntddk.h>
#include <minwindef.h>
#include <ntstrsafe.h>
#include "FunctionEntry.h"

#define MAX_STRING_LENGTH 128
#define CONDITION_TOKEN_LENGTH 10


char* replace(char* string, const char* substring, const char* replace) {

	// This function just changes the first occurence

	size_t string_length = strlen(string);
	size_t substring_length = strlen(substring);
	size_t replace_length = strlen(replace);
	size_t new_string_length = string_length + (replace_length - substring_length);
	char* match = nullptr;

	match = strstr(string, substring);
	if (match == nullptr) {
		// substring not found
		return string;
	}

	// Allocate memory
	char* new_string = (char*)ExAllocatePool2(POOL_FLAG_PAGED, new_string_length + 2, 'nskm');
	if (new_string == nullptr)
		return string;

	memset(new_string, 0, new_string_length + 2);

	strncpy_s(new_string, new_string_length + 2, string, (match - string));
	strncat_s(new_string, new_string_length + 2, replace, replace_length);
	strncat_s(new_string, new_string_length + 2, match + substring_length, string_length - (match - string - substring_length));

	// Free memory
	ExFreePool(string);

	return new_string;


}

bool boolean_expression_evaluator(char* file_data) {
	if (file_data == nullptr)
		return false;

	char expressions[20][20] = { "not(true)", "not(false)", "(true)", "(false)",
								"(true and false)", "(true and true)", "(false and true)", "(false and false)",
								"(true or false)", "(true or true)", "(false or true)", "(false or false)",
								"true and false", "true and true", "false and true", "false and false",
								"true or false", "true or true", "false or true", "false or false" };
	char expressions_output[20][8] = { "false", "true", "true", "false",
									   "(false)", "(true)", "(false)", "(false)",
									   "(true)", "(true)", "(true)", "(false)",
									   "false", "true", "false", "false",
									   "true", "true", "true", "false" };
	while (strlen(file_data) > 5) {
		for (int i = 0; i < 20; i++) {
			while (strstr(file_data, expressions[i]) != nullptr) {
				file_data = replace(file_data, expressions[i], expressions_output[i]);
			}
		}
	}


	if (strncmp(file_data, "true", 4) == 0) {
		// Free memory
		ExFreePool(file_data);
		return true;
	}
	else if (strncmp(file_data, "false", 5) == 0) {
		// Free memory
		ExFreePool(file_data);
		return false;
	}

	ExFreePool(file_data);
	return false;
}

char* process(char* file_data, PIMPORT_ENTRY ImportList) {


	// Process the file
	int count = 0;
	int ret = 0;
	size_t match_length = strlen("pe.imports(");
	size_t current_import_length = 0;
	char* start = file_data;
	char* match = nullptr;
	char* current_import = nullptr;


	do {
		match = strstr(start, "pe.imports(");
		if (match == nullptr)
			break;
		count++;
		start = match + match_length;
	} while (match != nullptr);

	// Allocate memory
	PIMPORT_ENTRY imports = (PIMPORT_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(IMPORT_ENTRY)*count, 'nskm');
	if (imports == nullptr) {
		ExFreePool(file_data);
		return nullptr;
	}

	memset(imports, 0, sizeof(IMPORT_ENTRY) * count);
	start = file_data;
	match = nullptr;

	for (size_t i = 0; i < count; i++) {
		match = strstr(start, "pe.imports(") + match_length;
		for (current_import_length = 0; match[current_import_length] != ')'; current_import_length++);

		// Allocate memory
		current_import = (char*)ExAllocatePool2(POOL_FLAG_PAGED, (current_import_length + 1)*sizeof(char), 'nskm');
		if (current_import != nullptr) {
			memset(current_import, 0, current_import_length + 1);
			strncpy_s(current_import, current_import_length + 1, match, current_import_length);

			ret = sscanf_s(current_import, "%[^','],%s", imports[i].dll_name, 128, imports[i].function_name, 128);;
			

			ExFreePool(current_import);
			current_import = nullptr;
		}
		else {
			ExFreePool(imports);
			ExFreePool(file_data);
			return nullptr;
		}

		start = match;
	}


	char imp_entry[300]{ 0 };
	bool exists = false;
	for (size_t i = 0; i < count; i++) {

		// Imports validation
		exists = false;
		for (size_t j = 0; j < 1024 && strlen(ImportList[i].dll_name) > 0 && strlen(ImportList[i].function_name) > 0;j++) {

			
			ANSI_STRING dll_name1;
			ANSI_STRING dll_name2;

			ANSI_STRING function_name1;
			ANSI_STRING function_name2;

			RtlInitAnsiString(&dll_name1, imports[i].dll_name);
			RtlInitAnsiString(&dll_name2, ImportList[j].dll_name);
			RtlInitAnsiString(&function_name1, imports[i].function_name);
			RtlInitAnsiString(&function_name2, ImportList[j].function_name);
			
			
			if (!RtlCompareString(&dll_name1, &dll_name2, TRUE) &&
				!RtlCompareString(&function_name1, &function_name2, TRUE)) {

				exists = true;
				break;
			}

		}
		
		sprintf_s(imp_entry, "pe.imports(%s, %s)", imports[i].dll_name, imports[i].function_name);

		if (exists)
			file_data = replace(file_data, imp_entry, "true");
		else
			file_data = replace(file_data, imp_entry, "false");
		memset(imp_entry, 0, 300);
	}

	// Free memory
	ExFreePool(imports);

	return file_data;

}


bool process_rules(char* data, size_t file_size, PIMPORT_ENTRY ImportList) {
	UNREFERENCED_PARAMETER(ImportList);
	//KdPrint(("[info] process_rules function reached\n"));
	char* file_data = (char*)ExAllocatePool2(POOL_FLAG_PAGED, file_size*sizeof(char) + 1, 'nskm');
	if (file_data == nullptr) {
		return false;
	}
	//KdPrint(("[info] Memory allocated for copy of yara_easy.txt\n"));

	RtlZeroMemory(file_data, file_size*sizeof(char) + 1);
	memcpy_s(file_data, file_size + 1, data, file_size);




	int count_rules = 0;
	char* temp = file_data;
	char* start = file_data;

	// Count number of rules
	for (count_rules = 0; temp != nullptr; count_rules++) {
		temp = strstr(temp, "drvnskm_rule");
		if (temp == nullptr)
			break;
		temp += 12;
	}
	
	temp = file_data;
	
	char rule_name[32]{ 0 };
	char* condition_section = nullptr;
	size_t condition_section_length = 0;
	size_t rule_name_length = 0;
	bool result = false;

	//KdPrint(("Process rules: Reading rules\n"));
	for (size_t i = 0; i < count_rules; i++) {
		// Process rules

		// Grab rule name
		temp = strstr(start, "drvnskm_rule") + CONDITION_TOKEN_LENGTH + 2;
		for (rule_name_length = 0; temp[rule_name_length] != '{' && rule_name_length < 32; rule_name_length++);
		strncpy_s(rule_name, 32, temp, rule_name_length);

		//KdPrint(("Processing rule (%s)\n", rule_name));
		// Condition section
		temp += rule_name_length + CONDITION_TOKEN_LENGTH + 1;
		for (condition_section_length = 0; temp[condition_section_length] != '}'; condition_section_length++);;

		// Memmory allocation
		condition_section = (char*)ExAllocatePool2(POOL_FLAG_PAGED, condition_section_length + 1, 'nskm');
		if (condition_section == nullptr) {
			//ExFreePool(file_data);
			break;
		}

		memset(condition_section, 0, condition_section_length + 1);
		strncpy_s(condition_section, condition_section_length + 1,temp, condition_section_length);

		// Evaluate
		
		condition_section = process(condition_section, ImportList);
		if (condition_section == nullptr) {
			ExFreePool(file_data);
			return false;
		}

		result = boolean_expression_evaluator(condition_section);
		//KdPrint(("[ RESULT ]: %d\n", result));
		if (result) {
			ExFreePool(file_data);
			return true;
		}
		// Next rule
		start = strstr(temp, "drvnskm_rule");
		memset(rule_name, 0, 32);
	}

	ExFreePool(file_data);
	return false;
}