#pragma once
#include <ntddk.h>
#define MAX_STRING_LENGTH 128

typedef struct _IMPORT_ENTRY_{
	char dll_name[MAX_STRING_LENGTH];
	char function_name[MAX_STRING_LENGTH];
} IMPORT_ENTRY, *PIMPORT_ENTRY;


bool process_rules(char* file_data, size_t file_size, PIMPORT_ENTRY);
