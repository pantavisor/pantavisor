/*
 * json-parser.c
 *
 *  Created on: 21-Jan-2021
 *      Author: gaurav
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <jsmn/jsmn.h>
#include <jsmn/jsmnutil.h>
#include "utils.h"
#include "utils/list.h"

typedef struct _devlist {
	struct dl_list next_match;
	char pv_devtype[32];	//store PV_DEVTYPE
	char **devname;			// should get malloced during runtime to store DEVNAME
	unsigned short int major;
	struct _apply {
		int perm;
		unsigned int gid;
		unsigned int uid;
	}apply;
}devlist;

int tsh_run_io(char *cmd, int wait, int *status,
		int stdin_p[], int stdout_p[], int stderr_p[]) {
	return 0;
}

static void dump_list(struct dl_list *head, int size)
{
	struct _devlist *t;
	int i = 0;
	printf("dump:\n");
	dl_list_for_each(t, head, struct _devlist, next_match) {
		printf("devtype: %s\nmajor: %d\ngid: %d\nuid: %d\nperm: %d\n", t->pv_devtype, t->major, t->apply.gid, t->apply.uid, t->apply.perm);
		for (i=0; i<size; i++)
			printf("devname: %s\n", t->devname[i]);
	}
//	dl_list_for_each(t, head, struct _devlist, next_match)
//			for (i=0; i<size; i++)
//				printf("devname: %s\n", t->devname[i]);

	printf(" (len=%d%s)\n", dl_list_len(head),
	       dl_list_empty(head) ? " empty" : "");
}


static int append (struct dl_list *head, char *pv_dtype, unsigned short int major, int gid, int perm, int uid, char **dname, int dnamesize) {
	struct _devlist *t;
	t = malloc(sizeof(*t));
	if (t == NULL)
		return -1;
	strcpy(t->pv_devtype, pv_dtype);
	t->major = major;
	t->apply.gid = gid;
	t->apply.perm = perm;
	t->apply.uid = uid;
	t->devname = calloc(1, (dnamesize + 1) * sizeof(char *));
	t->devname[dnamesize] = NULL;
	memcpy(t->devname, dname, ((dnamesize + 1) * sizeof(char *)));
	dl_list_add_tail(head, &t->next_match);
//	free(t);
}

int main(void) {

	FILE *json_fd;
	char *json_content, *key, *um;
	char *match, *apply, *pv_devtype, *DEVNAME, **tmp_devname, *str;//, *gid, *uid, *perm;
	int parse_rv, key_len, tokc, tok_c, size, major, perm, gid, uid, tmp_idx;
	long int json_len;
	size_t rv = 0;
	jsmn_parser p;
	jsmntok_t t[128]; /* We expect no more than 128 tokens */
	jsmntok_t *tokv, *tok_v;
	jsmntok_t **key_i, **keys, **keyss, *t_arr_tok;
	devlist *device_list;

	json_fd = fopen("devlist.json", "r");
	if(json_fd == NULL) {
		perror("Cannot open file");
		return -ENOENT;
	}
	if(fseek(json_fd, 0L, SEEK_END)) {
		perror("Cannot seek to end\n");
		return -EBADF;
	}
	json_len = ftell(json_fd);
	printf("Length of Json File: %ld\n", json_len);
	rewind(json_fd);

	json_content = malloc(json_len);
	if(json_content == NULL) {
		perror("Error during malloc\n");
		return -ENOMEM;
	}
	rv = fread(json_content, 1, json_len, json_fd);
	if((rv != json_len) || (rv == 0)) {
		perror("Cannot Read from json file\n");
		return -EXIT_FAILURE;
	}

	/**************************************************************************************************************/
	jsmn_init(&p);
	parse_rv = jsmn_parse(&p, json_content, json_len, t, sizeof(t)/sizeof(t[0]));
	if (parse_rv < 0) {
		printf("Failed to parse JSON: %d\n", parse_rv);
		return 1;
	}

	/* Assume the top-level element is an object */
	if (parse_rv < 1 || t[0].type != JSMN_OBJECT) {
		printf("Object expected\n");
		return 1;
	}
	jsmnutil_parse_json(json_content,&tokv, &tokc);
	um = get_json_key_value(json_content, "rules", tokv, tokc);
	if (!um) {
		rv = -1;
		goto out;
	}
	if (tokv)
		free(tokv);

	device_list = malloc(sizeof(*device_list));
	if (device_list == NULL)
		goto out;
	dl_list_init(&device_list->next_match);

	rv = jsmnutil_parse_json(um, &tokv, &tokc);
	keys = jsmnutil_get_array_toks(um, tokv);

	key_i = keys;

	while (*key_i) {

		key_len = (*key_i)->end - (*key_i)->start;

		// copy key
		key = malloc(key_len+1);
		if (!key)
			break;

		snprintf(key, key_len+1, "%s", um+(*key_i)->start);
		rv = jsmnutil_parse_json(key, &tok_v, &tok_c);

		match = get_json_key_value(key, "match", tok_v, tok_c);
		apply = get_json_key_value(key, "apply", tok_v, tok_c);

		if (!apply) {
			rv = -1;
			goto out;
		}
		if (!match) {
			rv = -1;
			goto out;
		}

		if (tok_v) {
			free(tok_v);
			tok_v = 0;
		}

		rv = jsmnutil_parse_json(apply, &tok_v, &tok_c);
		perm = get_json_key_value_int(apply, "perm", tok_v, tok_c);
		gid = get_json_key_value_int(apply, "gid", tok_v, tok_c);
		uid = get_json_key_value_int(apply, "uid", tok_v, tok_c);
	//		printf("perm: %d gid: %d uid: %d\n", perm, gid, uid);
		if (tok_v) {
			free(tok_v);
			tok_v = 0;
		}

		rv = jsmnutil_parse_json(match, &tok_v, &tok_c);
		pv_devtype = get_json_key_value(match, "PV_DEVTYPE", tok_v, tok_c);
		major = get_json_key_value_int(match, "MAJOR", tok_v, tok_c);
		DEVNAME = get_json_key_value(match, "DEVNAME", tok_v, tok_c);

//		printf("Major: %d\n", major);

		if (tok_v) {
			free(tok_v);
			tok_v = 0;
		}
		rv = jsmnutil_parse_json(DEVNAME, &tok_v, &tok_c);
		keyss = jsmnutil_get_array_toks(DEVNAME, tok_v);
		key_len = size = jsmnutil_array_count(DEVNAME, tok_v);
		t_arr_tok = tok_v+1;
		tmp_devname = calloc(1, (size + 1) * sizeof(char *));
		tmp_devname[size] = NULL;

		tmp_idx = 0;
		while ((str = json_array_get_one_str(DEVNAME, &size, &t_arr_tok))) {
			tmp_devname[tmp_idx] = str;
			tmp_idx++;
		}

		if (tok_v) {
			free(tok_v);
			tok_v = 0;
		}

		append(&device_list->next_match, pv_devtype, major, gid, perm, uid, tmp_devname, key_len);

		if (key) {
			free(key);
			key = 0;
		}

		if(keyss) {
			jsmnutil_tokv_free(keyss);
			keyss = 0;
		}
		if (tok_v) {
			free(tok_v);
			tok_v = 0;
		}
		if(match)
		{
			free(match);
			match = 0;
		}
		if(apply)
		{
			free(apply);
			apply = 0;
		}
		if(pv_devtype)
		{
			free(pv_devtype);
			pv_devtype = 0;
		}
		key_i++;
		dump_list(&device_list->next_match, key_len);
	}
	out:
	if (tokv) {
		free(tokv);
		tokv = 0;
	}
	if (tok_v) {
		free(tok_v);
		tok_v = 0;
	}
	if(um)
	{
		free(um);
		um = 0;
	}
	if(keys) {
		jsmnutil_tokv_free(keys);
		keys = 0;
	}
	if(json_content) {
		free(json_content);
		json_content = 0;
	}
	fclose(json_fd);

	return rv;
}
