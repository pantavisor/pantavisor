#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "utils/tsh.h"

#define SIZE 10000

int main(int argc, char **argv)
{
	char out[SIZE], err[SIZE];
	int ret;

	memset(out, 0, SIZE);
	memset(err, 0, SIZE);
	if (argc > 1)
		ret = tsh_run_output(argv[1], 2, out, SIZE, err, SIZE);
	else
		ret = tsh_run_output("/bin/ls /", 2, out, SIZE, err, SIZE);

	printf("ret: %d; errno: %s; out: %s; err: %s\n", ret, strerror(errno),
	       out, err);

	return 0;
}
