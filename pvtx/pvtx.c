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
#include "utils/fs.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <linux/limits.h>

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
#define LOCAL_ERR(msg) local_err(__FILE__, __LINE__, msg)

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

static void local_err(const char *file, int line, const char *msg)
{
	char bname[NAME_MAX] = { 0 };
	pv_fs_basename(file, bname);
	fprintf(stderr, "ERROR: %s\n(%s:%d)\n", msg, bname, line);
}

static int cmd_begin(int argc, char **argv)
{
	struct pv_pvtx_error err = { 0 };
	char *from = NULL;
	char *obj_path = NULL;

	if (argc < 3)
		from = "current";
	else
		from = argv[2];

	if (argc > 3)
		obj_path = argv[3];

	int ret = pv_pvtx_txn_begin(from, obj_path, &err);
	if (ret != 0)
		fprintf(stderr, "ERROR: %s\n", err.str);

	return ret;
}
static int cmd_add(int argc, char **argv)
{
	if (argc < 3) {
		LOCAL_ERR("missing argument, files or - is needed");
		return -1;
	}

	struct pv_pvtx_error err = { 0 };
	int ret = 0;

	if (argv[2][0] == '-')
		ret = pv_pvtx_txn_add_tar_from_fd(STDIN_FILENO, &err);
	else
		ret = pv_pvtx_txn_add_from_disk(argv[2], &err);

	if (ret != 0)
		fprintf(stderr, "ERROR: %s\n", err.str);

	return ret;
}
static int cmd_remove(int argc, char **argv)
{
	if (argc < 3) {
		LOCAL_ERR("must remove a part, missing parameter");
		return 4;
	}

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
	char *rev = pv_pvtx_txn_commit(&err);
	if (!rev) {
		fprintf(stderr, "ERROR: %s\n", err.str);
		free(rev);
	} else {
		printf("%s\n", rev);
	};

	return err.code;
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
		LOCAL_ERR("missing deploy folder");
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
	printf("Usage: %s COMMAND [SUB-COMMAND] args...\n\n", argv[0]);
	printf("Commands:\n");

	printf("  %-22s", "begin <base> [object]");
	printf("Creates a new transaction.\n");
	printf("%-24s%s\n", " ",
	       "The first argument <base> could be a real revision,");
	printf("%-24s%s\n", " ",
	       "\"\" (empty string, use current rev) or \"empty\" (empty revision).");
	printf("%-24s%s\n", " ",
	       "Transactions created without an object_path are called remote");
	printf("%-24s%s\n", " ",
	       "transactions and its objects sent directly to the pv-ctrl socket.");
	printf("  %-22s", "add <file> or -");
	printf("Adds a json or tarball to the current transaction.\n");
	printf("%-24s%s\n", " ",
	       "Alternatively '-' could be used to read from stdin.");
	printf("  %-22s", "abort");
	printf("Commit transaction, valid only for remote transactions.\n");
	printf("  %-22s", "commit");
	printf("Show the current state json.\n");
	printf("  %-22s", "show");
	printf("Show the current state json.\n");
	printf("  %-22s", "deploy <directory>");
	printf("Deploy the current transaction in the given directory.\n");
	printf("  %-22s", "help <file>");
	printf("Show this help and ends.\n");
	printf("  %-22s", "queue <sub-command>");
	printf("This command uses the queue mode and requires a sub-command.\n\n");

	printf("Queue Sub-commands:\n");
	printf("  %-22s", "new <queue> <object>");
	printf("Creates a new queue at queue and save objects at object.\n");
	printf("  %-22s", "remove <path>");
	printf("Remove the given part from the current queue.\n");
	printf("  %-22s", "unpack <tarball>");
	printf("Unpack the given tarbal.\n");
	printf("  %-22s", "process");
	printf("Process the current queue.\n");

	printf("Environment Variables:\n");
	printf("  %-22s", "PVTXDIR");
	printf("Temporary directory where PVTX store transaction related data\n");
	printf("  %-22s", "PVTX_OBJECT_BUF_SIZE");
	printf("Size of the buffer used to save objects. Min 512B max 10485760B (10M)\n");
	printf("  %-22s", "PVTX_CTRL_BUF_SIZE");
	printf("Size of the buffer used to get and post data to pv-ctrl.\n");
	printf("%-24s%s\n", " ", "Min 16384B (16K) max 10485760B (10M)\n");

	return 0;
}

static int cmd_queue_new(int argc, char **argv)
{
	if (argc < 4) {
		LOCAL_ERR("queue argument is required");
		return 1;
	} else if (argc < 5) {
		LOCAL_ERR("objects argument is required");
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
		LOCAL_ERR("missing argument 'part'");
		return 1;
	}

	struct pv_pvtx_error err = { 0 };
	int ret = pv_pvtx_queue_remove(argv[3], &err);
	if (ret != 0)
		fprintf(stderr, "ERROR: %s\n", err.str);

	return ret;
}
static int cmd_queue_unpack(int argc, char **argv)
{
	if (argc < 4) {
		LOCAL_ERR("missing argument, file or - is required");
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

	// NOTE: the third argument is the first important for the function
	// because 0: program name; 1: "queue"; 2: "process"
	for (int i = 3, j = 0; i < argc; ++i) {
		var[j] = argv[i];
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

	if (!strlen(op)) {
		LOCAL_ERR("empty command");
		cmd_help(argc, argv);
		exit(1);
	}

	if (!strncmp(op, "queue", strlen(op))) {
		op = argv[2];
		cmd = &queue;
	}

	int err = 0;
	for (int i = 0; i < cmd->size; ++i) {
		if (strncmp(op, cmd->names[i], strlen(cmd->names[i])))
			continue;

		err = cmd->fn[i](argc, argv);
		return err;
	}

	char e[256] = { 0 };
	snprintf(e, 256, "command not found: %s", op);

	LOCAL_ERR(e);

	return -1;
}

int main(int argc, char **argv)
{
	return pv_pvtx_process_args(argc, argv);
}