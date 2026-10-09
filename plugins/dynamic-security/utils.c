#include "dynamic_security.h"

void enforce_priority_limits(int *priority)
{
	if(*priority > PRIORITY_MAX){
		*priority = PRIORITY_MAX;
	} else if(*priority < PRIORITY_MIN){
		*priority = PRIORITY_MIN;
	}
}

