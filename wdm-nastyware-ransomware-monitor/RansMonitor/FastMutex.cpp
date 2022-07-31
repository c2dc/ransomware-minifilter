#include "FastMutex.h"


void FastMutex::Init() {
	ExInitializeFastMutex(&this->_mutex);
}

void FastMutex::Lock() {
	ExAcquireFastMutex(&this->_mutex);
}

void FastMutex::Unlock() {
	ExReleaseFastMutex(&this->_mutex);
}