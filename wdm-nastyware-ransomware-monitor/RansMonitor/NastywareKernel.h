#pragma once
#include "FastMutex.h"

typedef struct NASTYWARE_MON_PROCESS_NODE {
	ULONG ProcessId;
	LIST_ENTRY Entry;
} *PNASTYWARE_MON_PROCESS_NODE;

struct Globals {
	LIST_ENTRY listHead;
	FastMutex Mutex;
	unsigned int Count;
	bool ProcessAPI;
};