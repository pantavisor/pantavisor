
#include <stdio.h>
#include <string.h>

#include "utils/tsh.h"

#define SIZE 10000

int main()
{
	char out[SIZE], err[SIZE];
	int ret;

	memset(out, 0, SIZE);
	memset(err, 0, SIZE);
	ret = tsh_run_output("/bin/ls /", 5, out, SIZE, err, SIZE);
	printf("ret: %d; out: %s; err: %s\n", ret, out, err);

	return 0;
}
