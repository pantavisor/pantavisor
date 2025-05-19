/*
 * Copyright (c) 2023 Pantacor Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "disk/disk_zram_utils.h"

#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

static char doc[] = "Provision a new zram device";
static struct argp_option options[] = {
	{ "find", 'f', "DEVICE", OPTION_ARG_OPTIONAL,
	  "Find the next available device. If there are not device availables, a new device is crerated. If a device is provided and it's available it will be used." },
	{ "algorithm", 'a', "ALGORITHM", 0, "Set the compression algorithm." },
	{ "reset", 'r', "DEVICE", 0, "Reset a device." },
	{ "size", 's', "SIZE", 0, "Set the disk size." },
	{ "streams", 't', "NUMBER", 0,
	  "Set the maximum number of compression streams." },
	{ 0 }
};

struct arguments {
	char *alg;
	char *size;
	char *n_stream;
	char *reset;
	char *find;
	bool find_new;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *args = state->input;
	switch (key) {
	case 'a':
		args->alg = arg;
		break;
	case 'r':
		args->reset = arg;
		break;
	case 's':
		args->size = arg;
		break;
	case 't':
		args->n_stream = arg;
		break;
	case 'f':
		if (arg)
			args->find = arg;
		else
			args->find_new = true;
		break;
	case ARGP_KEY_ARG:
		return 0;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, NULL, doc, 0, 0, 0 };

int main(int argc, char **argv)
{
	struct arguments arguments = { NULL, NULL, NULL, NULL, NULL, false };
	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	if (arguments.reset) {
		int devno = pv_disk_zram_utils_get_devno(arguments.reset);
		return pv_disk_zram_utils_reset(devno) < 0 ? -1 : 0;
	}

	int devno = -1;
	if (!arguments.find_new) {
		devno = pv_disk_zram_utils_get_devno(arguments.find);
	} else {
		devno = pv_disk_zram_utils_find_or_create_device();
	}

	if (devno < 0) {
		fprintf(stderr, "Error, cannot get a valid device\n");
		return -1;
	}

	char *path = pv_disk_zram_utils_get_path(devno);

	if (arguments.n_stream &&
	    pv_disk_zram_utils_set_streams(devno, arguments.n_stream) < 0)
		fprintf(stderr,
			"Error, cannot set the compression streams for %s\n",
			path);

	if (arguments.alg &&
	    pv_disk_zram_utils_set_compression(devno, arguments.alg) < 0)
		fprintf(stderr,
			"Error, cannot set the compression algorithm for %s\n",
			path);

	if (arguments.size &&
	    pv_disk_zram_utils_set_size(devno, arguments.size) < 0)
		fprintf(stderr, "Error, cannot set the disk size for %s\n",
			path);

	printf("%s\n", path);

	free(path);
	return 0;
}
