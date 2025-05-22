/*
 * Copyright (c) 2025 Pantacor Ltd.
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

#include "pvtx_txn.h"
#include "pvtx_error.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

static int cmd_begin(int argc, char **argv);
static int cmd_add(int argc, char **argv);
static int cmd_remove(int argc, char **argv);
static int cmd_abort(int argc, char **argv);
static int cmd_commit(int argc, char **argv);
static int cmd_show(int argc, char **argv);
static int cmd_deploy(int argc, char **argv);
static int cmd_help(int argc, char **argv);
static int cmd_queue_new(int argc, char **argv);
static int cmd_queue_remove(int argc, char **argv);
static int cmd_queue_unpack(int argc, char **argv);
static int cmd_queue_process(int argc, char **argv);

typedef int (*func)(int argc, char **argv);

struct commands {
	const char **names;
	const func *fn;
	int size;
};

#define PVTX_DIR_VAR "PVTXDIR"

static struct commands normal = {
	.names =
		(const char *[]){
			"begin",
			"add",
			"remove",
			"abort",
			"commit",
			"show",
			"deploy",
			"help",
		},
	.fn =
		(const func[]){
			cmd_begin,
			cmd_add,
			cmd_remove,
			cmd_abort,
			cmd_commit,
			cmd_show,
			cmd_deploy,
			cmd_help,
		},
	.size = 8,
};

static struct commands queue = {
	.names =
		(const char *[]){
			"new",
			"remove",
			"unpack",
			"process",
		},
	.fn =
		(const func[]){
			cmd_queue_new,
			cmd_queue_remove,
			cmd_queue_unpack,
			cmd_queue_process,
		},
	.size = 4,
};

static int cmd_begin(int argc, char **argv)
{
	struct pv_pvtx_error err = { 0 };
	char *from = NULL;
	char *obj_path = NULL;

	if (argc > 2)
		from = argv[2];
	if (argc > 3)
		obj_path = argv[3];

	int ret = pv_pvtx_txn_begin(from, obj_path, &err);
	if (ret != 0)
		fprintf(stderr, "%s", err.str);

	return ret;
}
static int cmd_add(int argc, char **argv)
{
	if (argc < 2)
		return -1;

	struct pv_pvtx_error err = { 0 };
	int ret = 0;

	if (argv[2][0] == '-') {
		printf("adding pvexport from stdin\n");
		ret = pv_pvtx_txn_add_tar_from_fd(STDIN_FILENO, &err);
	} else {
		printf("adding from %s\n", argv[2]);
		ret = pv_pvtx_txn_add_from_disk(argv[2], &err);
	}

	if (ret != 0)
		fprintf(stderr, "ERROR: %s\n", err.str);

	return ret;
}
static int cmd_remove(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr,
			"ERROR: must remove a part (missing paramter)\n");
		return 4;
	}

	printf("removing %s and cleaning signed files if part has been signed\n",
	       argv[2]);

	struct pv_pvtx_error err = { 0 };
	int ret = pv_pvtx_txn_remove(argv[2], &err);

	if (ret != 0)
		fprintf(stderr, "ERROR: %s\n", err.str);

	return ret;
}
static int cmd_abort(int argc, char **argv)
{
	struct pv_pvtx_error err = { 0 };
	int ret = pv_pvtx_txn_abort(&err);
	if (ret != 0)
		fprintf(stderr, "ERROR: %s\n", err.str);
	return ret;
}
static int cmd_commit(int argc, char **argv)
{
	struct pv_pvtx_error err = { 0 };
	int ret = pv_pvtx_txn_commit(&err);
	if (ret != 0)
		fprintf(stderr, "ERROR: %s\n", err.str);
	return ret;
}
static int cmd_show(int argc, char **argv)
{
	struct pv_pvtx_error err = { 0 };
	char *json = pv_pvtx_txn_get_json(&err);
	if (!json) {
		fprintf(stderr, "ERROR: %s\n", err.str);
		return err.code;
	}

	printf("%s\n", json);
	free(json);

	return 0;
}
static int cmd_deploy(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "ERROR: missing deploy folder\n");
		return 1;
	}

	struct pv_pvtx_error err = { 0 };
	int ret = pv_pvtx_txn_deploy(argv[2], &err);

	if (ret != 0) {
		fprintf(stderr, "ERROR: %s\n", err.str);
	}

	return ret;
}

static int cmd_help(int argc, char **argv)
{
	printf("help:\n");
	return 0;
}

static int cmd_queue_new(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "ERROR: queue argument is required\n");
		return 1;
	} else if (argc < 5) {
		fprintf(stderr, "ERROR: objects argument is required\n");
		return 1;
	}

	struct pv_pvtx_error err = { 0 };

	int ret = pv_pvtx_queue_new(argv[3], argv[4], &err);
	if (ret != 0)
		fprintf(stderr, "ERROR: %s\n", err.str);

	return ret;
}
static int cmd_queue_remove(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "ERROR: missing argument 'part'\n");
		return 1;
	}

	printf("adding remove operation for %s to queue\n", argv[3]);

	struct pv_pvtx_error err = { 0 };
	int ret = pv_pvtx_queue_remove(argv[3], &err);
	if (ret != 0)
		fprintf(stderr, "ERROR: %s\n", err.str);

	return ret;
}
static int cmd_queue_unpack(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "ERROR: missing argument 'part'\n");
		return 1;
	}

	struct pv_pvtx_error err = { 0 };
	int ret = 0;

	if (argv[3][0] == '-')
		ret = pv_pvtx_queue_unpack_tar_from_fd(STDIN_FILENO, &err);
	else
		ret = pv_pvtx_queue_unpack_from_disk(argv[3], &err);

	if (ret != 0)
		fprintf(stderr, "ERROR: %s\n", err.str);

	return ret;
}
static int cmd_queue_process(int argc, char **argv)
{
	// v[0] base trail
	// v[1] queue directory
	// v[2] object directory
	char *var[3] = { 0 };
	struct pv_pvtx_error err = { 0 };

	for (int i = 3, j = 0; i < argc; ++i) {
		printf("argv[%d] = %s\n", i, argv[i]);
		var[j] = argv[i];

		printf("var[%d]  = %s\n\n", j, var[j]);
		j++;
	}

	int ret = pv_pvtx_queue_process(var[0], var[1], var[2], &err);

	if (ret != 0)
		fprintf(stderr, "ERROR: %s\n", err.str);

	return ret;
}

static int pv_pvtx_process_args(int argc, char **argv)
{
	if (argc < 2) {
		cmd_help(argc, argv);
		return -1;
	}

	char *op = argv[1];
	struct commands *cmd = &normal;

	if (!strncmp(op, "queue", strlen(op))) {
		op = argv[2];
		cmd = &queue;
	}

	int err = 0;
	for (int i = 0; i < cmd->size; ++i) {
		if (strncmp(op, cmd->names[i], strlen(cmd->names[i])))
			continue;

		err = cmd->fn[i](argc, argv);
		if (err != 0)
			fprintf(stderr, "command finish with errors err = %d\n",
				err);
		return err;
	}

	fprintf(stderr, "command not found\n");

	return -1;
}

int main(int argc, char **argv)
{
	return pv_pvtx_process_args(argc, argv);
}