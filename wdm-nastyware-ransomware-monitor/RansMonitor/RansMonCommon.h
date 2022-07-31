#pragma once
#define IOCTL_NASTYWARE_MON_KILL_PROCESS CTL_CODE(0x8000, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct NASTYWARE_MON_PROCESS {
	unsigned long processId;
	bool isRansomware;
} *PNASTYWARE_MON_PROCESS;