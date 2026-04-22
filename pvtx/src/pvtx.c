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

#include <pvtx/txn.h>
#include <pvtx/error.h>
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

static struct commands normal = {
	.names = (const char *[]){ "begin", "add", "remove", "abort", "commit",
				   "show", "deploy", "help", "--help" },
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
			cmd_help,
		},
	.size = 9,
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
		pv_pvtx_error_print(&err, "begin");

	return ret;
}
static int cmd_add(int argc, char **argv)
{
	if (argc < 3) {
		pv_pvtx_error_print_raw(
			"add", "missing argument, file or - is needed");
		return -1;
	}

	struct pv_pvtx_error err = { 0 };
	int ret = 0;

	if (argv[2][0] == '-')
		ret = pv_pvtx_txn_add_tar_from_fd(STDIN_FILENO, &err);
	else
		ret = pv_pvtx_txn_add_from_disk(argv[2], &err);

	if (ret != 0)
		pv_pvtx_error_print(&err, "add");

	return ret;
}
static int cmd_remove(int argc, char **argv)
{
	if (argc < 3) {
		pv_pvtx_error_print_raw("remove", "must supply a part name");
		return 4;
	}

	struct pv_pvtx_error err = { 0 };
	int ret = pv_pvtx_txn_remove(argv[2], &err);

	if (ret != 0)
		pv_pvtx_error_print(&err, "remove");

	return ret;
}
static int cmd_abort(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	struct pv_pvtx_error err = { 0 };
	int ret = pv_pvtx_txn_abort(&err);
	if (ret != 0)
		pv_pvtx_error_print(&err, "abort");
	return ret;
}
static int cmd_commit(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	struct pv_pvtx_error err = { 0 };
	char *rev = pv_pvtx_txn_commit(&err);
	if (!rev) {
		pv_pvtx_error_print(&err, "commit");
	} else {
		printf("%s\n", rev);
		free(rev);
	};

	return err.code;
}
static int cmd_show(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	struct pv_pvtx_error err = { 0 };
	char *json = pv_pvtx_txn_get_json(&err);
	if (!json) {
		pv_pvtx_error_print(&err, "show");
		return err.code;
	}

	printf("%s\n", json);
	free(json);

	return 0;
}
static int cmd_deploy(int argc, char **argv)
{
	if (argc < 3) {
		pv_pvtx_error_print_raw("deploy", "missing deploy folder");
		return 1;
	}

	struct pv_pvtx_error err = { 0 };
	int ret = pv_pvtx_txn_deploy(argv[2], &err);

	if (ret != 0) {
		pv_pvtx_error_print(&err, "deploy");
	}

	return ret;
}

static int cmd_help(int argc, char **argv)
{
	(void)argc;

	printf("Usage: %s COMMAND [SUB-COMMAND] args...\n\n", argv[0]);
	printf("pvtx manages Pantavisor revision transactions. A transaction\n");
	printf("starts with 'begin', is built up with 'add'/'remove', and is\n");
	printf("finalized with either 'commit' (remote) or 'deploy' (local).\n\n");

	printf("Commands:\n");

	printf("  %-30s", "begin <base> [object]");
	printf("Start a new transaction based on an existing revision.\n");
	printf("%-32s%s\n", " ",
	       "<base> can be \"current\" (copy state from the running Pantavisor");
	printf("%-32s%s\n", " ",
	       "via pv-ctrl), \"empty\" (start from a blank revision), or a path");
	printf("%-32s%s\n", " ", "to a revision directory or state JSON file.");
	printf("%-32s%s\n", " ",
	       "If [object] is given, the transaction is local: objects are saved");
	printf("%-32s%s\n", " ",
	       "to that directory and finalized with 'deploy'. Without [object],");
	printf("%-32s%s\n", " ",
	       "the transaction is remote: objects are streamed to pv-ctrl and");
	printf("%-32s%s\n", " ", "finalized with 'commit'.");

	printf("  %-30s", "add <file | ->");
	printf("Add a package to the current transaction.\n");
	printf("%-32s%s\n", " ",
	       "<file> can be a state JSON file or a gzip tarball containing a");
	printf("%-32s%s\n", " ",
	       "\"json\" descriptor and an \"objects/\" directory with content");
	printf("%-32s%s\n", " ",
	       "files named by their SHA-256 hash. Use '-' to read a tarball");
	printf("%-32s%s\n", " ",
	       "from stdin. For remote transactions, objects are uploaded to");
	printf("%-32s%s\n", " ",
	       "pv-ctrl directly; for local ones, saved to the object dir.");
	printf("  %-30s", "remove <part>");
	printf("Remove a named part (container/component) from the current\n");
	printf("%-32s%s\n", " ", "transaction's state JSON.");

	printf("  %-30s", "abort");
	printf("Discard the current transaction, deleting the in-progress\n");
	printf("%-32s%s\n", " ", "state JSON and transaction status file.");

	printf("  %-30s", "commit");
	printf("Finalize a remote transaction by sending the state JSON to\n");
	printf("%-32s%s\n", " ",
	       "Pantavisor via the pv-ctrl socket. Generates and prints a");
	printf("%-32s%s\n", " ",
	       "revision name (locals/pvtx-<timestamp>-<hash>-<rand>).");
	printf("%-32s%s\n", " ",
	       "Only valid for remote transactions (begun without [object]).");

	printf("  %-30s", "show");
	printf("Print the in-progress state JSON of the current transaction.\n");

	printf("  %-30s", "deploy <directory>");
	printf("Finalize a local transaction by writing the revision layout\n");
	printf("%-32s%s\n", " ",
	       "to <directory>. Creates .pvr/json, .pvr/config, hard-links");
	printf("%-32s%s\n", " ",
	       "objects from the object dir, and sets up .pv/ BSP links.");
	printf("%-32s%s\n", " ",
	       "Performs a safe atomic-like swap: the old directory is kept");
	printf("%-32s%s\n", " ", "as <directory>.bak until deploy succeeds.");
	printf("%-32s%s\n", " ",
	       "Only valid for local transactions (begun with [object]).");

	printf("  %-30s", "help | --help");
	printf("Show this help message.\n");

	printf("  %-30s", "queue <sub-command>");
	printf("Operate in queue mode, which records an ordered sequence of\n");
	printf("%-32s%s\n", " ",
	       "add/remove steps and replays them atomically in one 'process'");
	printf("%-32s%s\n", " ",
	       "call. Useful for batching multiple package updates together.");

	printf("\nQueue Sub-commands:\n");

	printf("  %-30s", "new <queue> <object>");
	printf("Initialize a new queue. <queue> is the directory where step\n");
	printf("%-32s%s\n", " ",
	       "files are stored in order; <object> is the directory where");
	printf("%-32s%s\n", " ", "unpacked content objects will be saved.");

	printf("  %-30s", "remove <part>");
	printf("Schedule a remove step for <part> in the current queue.\n");
	printf("%-32s%s\n", " ",
	       "Creates a numbered .remove marker that 'queue process' will");
	printf("%-32s%s\n", " ", "apply in sequence.");

	printf("  %-30s", "unpack <tarball|->");
	printf("Stage a package into the current queue. Extracts the state\n");
	printf("%-32s%s\n", " ",
	       "JSON descriptor and saves objects to the object directory.");
	printf("%-32s%s\n", " ",
	       "Each call adds a numbered step entry. Use '-' for stdin.");

	printf("  %-30s", "process [base [queue obj]]");
	printf("Replay all queued steps in order to build a final revision.\n");
	printf("%-32s%s\n", " ",
	       "Applies add directories and .remove markers alphabetically.");
	printf("%-32s%s\n", " ",
	       "base : revision to start from (\"current\", \"empty\", or path).");
	printf("%-32s%s\n", " ",
	       "queue: queue directory path; implicitly calls 'queue new'");
	printf("%-32s%s\n", " ",
	       "       when provided (requires obj to be set as well).");
	printf("%-32s%s\n", " ",
	       "obj  : object directory path; required when queue is given.");
	printf("%-32s%s\n", " ",
	       "When called with no arguments, resumes the active queue and");
	printf("%-32s%s\n", " ", "active transaction.");

	printf("\nEnvironment Variables:\n");
	printf("  %-30s", "PVTXDIR");
	printf("Directory where pvtx stores transaction state (status file\n");
	printf("%-32s%s\n", " ",
	       "and current.json). Default (root): /var/cache/pvtx");
	printf("%-32s%s\n", " ",
	       "Default (user): ~/.local/share/pvtx");
	printf("  %-30s", "PVTX_OBJECT_BUF_SIZE");
	printf("I/O buffer size for reading/writing object files.\n");
	printf("%-32s%s\n", " ",
	       "Min 512B, max 10485760B (10M). Default: 512B.");
	printf("  %-30s", "PVTX_CTRL_BUF_SIZE");
	printf("I/O buffer size for communicating with pv-ctrl socket.\n");
	printf("%-32s%s\n", " ", "Min 16384B (16K), max 10485760B (10M).\n");

	return 0;
}

static int cmd_queue_new(int argc, char **argv)
{
	if (argc < 4) {
		pv_pvtx_error_print_raw("queue new",
					"queue argument is required");
		return 1;
	} else if (argc < 5) {
		pv_pvtx_error_print_raw("queue new",
					"objects argument is required");
		return 1;
	}

	struct pv_pvtx_error err = { 0 };

	int ret = pv_pvtx_queue_new(argv[3], argv[4], &err);
	if (ret != 0)
		pv_pvtx_error_print(&err, "queue new");

	return ret;
}
static int cmd_queue_remove(int argc, char **argv)
{
	if (argc < 4) {
		pv_pvtx_error_print_raw("queue remove",
					"missing argument 'part'");
		return 1;
	}

	struct pv_pvtx_error err = { 0 };
	int ret = pv_pvtx_queue_remove(argv[3], &err);
	if (ret != 0)
		pv_pvtx_error_print(&err, "queue remove");

	return ret;
}
static int cmd_queue_unpack(int argc, char **argv)
{
	if (argc < 4) {
		pv_pvtx_error_print_raw(
			"queue unpack",
			"missing argument, file or - is required");
		return 1;
	}

	struct pv_pvtx_error err = { 0 };
	int ret = 0;

	if (argv[3][0] == '-')
		ret = pv_pvtx_queue_unpack_tar_from_fd(STDIN_FILENO, &err);
	else
		ret = pv_pvtx_queue_unpack_from_disk(argv[3], &err);

	if (ret != 0)
		pv_pvtx_error_print(&err, "queue unpack");

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
		pv_pvtx_error_print(&err, "queue process");

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

	pv_pvtx_error_print_raw("command process",
				"sub command not found: %s\nplease use 'help' "
				"to find the right sub command",
				op);

	return -1;
}

int main(int argc, char **argv)
{
	return pv_pvtx_process_args(argc, argv);
}
