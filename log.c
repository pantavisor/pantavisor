#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"

void exit_error(int err, char *msg)
{
	printf("ERROR: %s (err=%d)\n", msg, err);
	sleep(1);
	exit(0);
}
