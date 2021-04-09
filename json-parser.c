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
#include "json-parser.h"

int tsh_run_io(char *cmd, int wait, int *status,
		int stdin_p[], int stdout_p[], int stderr_p[]) {
	return 0;
}

static void free_list(struct dl_list *head)
{
	struct _match *t;
	dl_list_for_each(t, head, struct _match, next_match) {
		for(int i=0; i<t->devname_size; i++) {
			if(t->devname) {
				free(t->devname);
				t->devname = 0;
			}
		}
	}
}

static int append (struct dl_list *head, char **pv_action, int actkeylen, char *subsys,
		char *vid, char *model, int gid, int perm, int uid, char **dname, int dnamesize) {
	match *tmp_list;
	tmp_list = malloc(sizeof(*tmp_list));
	if (tmp_list == NULL)
		return -1;
	memcpy(tmp_list->action, pv_action, ((actkeylen + 1) * sizeof(char *)));
	strcpy(tmp_list->subsystem, subsys);
	strcpy(tmp_list->vendor_id, vid);
	strcpy(tmp_list->model_id, model);
	tmp_list->apply.gid = gid;
	tmp_list->apply.perm = perm;
	tmp_list->apply.uid = uid;
	tmp_list->devname = calloc(1, (dnamesize + 1) * sizeof(char *));
	tmp_list->devname[dnamesize] = NULL;
	tmp_list->devname_size = dnamesize;
	memcpy(tmp_list->devname, dname, ((dnamesize + 1) * sizeof(char *)));
	dl_list_add_tail(head, &tmp_list->next_match);
//	free(tmp_list);
	return 0;
}

struct dl_list *parse_json(void) {

	FILE *json_fd;
	char *json_content, *key, *um;
	char *match_p, *apply, *action, **tmp_action, *subsys, *vid, *model, *DEVNAME, **tmp_devname, *str;//, *gid, *uid, *perm;
	int parse_rv, key_len, act_key_len, tokc, tok_c, arr_tok_c, size, perm, gid, uid, tmp_idx;
	long int json_len;
	size_t rv = 0;
	jsmn_parser p;
	jsmntok_t t[128]; /* We expect no more than 128 tokens */
	jsmntok_t *tokv, *tok_v, *arr_tok_v;
	jsmntok_t **key_i, **keys, **keyss, *t_arr_tok;
	match *device_list;

	json_fd = fopen("devlist.json", "r");
	if(json_fd == NULL) {
		perror("Cannot open file");
		rv = -ENOENT;
		exit(rv);
	}
	if(fseek(json_fd, 0L, SEEK_END)) {
		perror("Cannot seek to end\n");
		rv = -EBADF;
		exit(rv);
	}
	json_len = ftell(json_fd);
	printf("Length of Json File: %ld\n", json_len);
	rewind(json_fd);

	json_content = malloc(json_len);
	if(json_content == NULL) {
		perror("Error during malloc\n");
		rv = -ENOMEM;
		exit(rv);
	}
	rv = fread(json_content, 1, json_len, json_fd);
	if((rv != json_len) || (rv == 0)) {
		perror("Cannot Read from json file\n");
		rv = -EXIT_FAILURE;
		exit(rv);
	}

	/**************************************************************************************************************/
	jsmn_init(&p);
	parse_rv = jsmn_parse(&p, json_content, json_len, t, sizeof(t)/sizeof(t[0]));
	if (parse_rv < 0) {
		printf("Failed to parse JSON: %d\n", parse_rv);
		rv = -1;
		exit(rv);
	}

	/* Assume the top-level element is an object */
	if (parse_rv < 1 || t[0].type != JSMN_OBJECT) {
		printf("Object expected\n");
		rv = 1;
		exit(rv);
	}
	jsmnutil_parse_json(json_content, &tokv, &tokc);
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
//	dl_list_init(&head);

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

		match_p = get_json_key_value(key, "match", tok_v, tok_c);
		apply = get_json_key_value(key, "apply", tok_v, tok_c);

		if (!apply) {
			rv = -1;
			goto out;
		}
		if (!match_p) {
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
		if (tok_v) {
			free(tok_v);
			tok_v = 0;
		}

		rv = jsmnutil_parse_json(match_p, &tok_v, &tok_c);
		action = get_json_key_value(match_p, "ACTION", tok_v, tok_c);

		rv = jsmnutil_parse_json(action, &arr_tok_v, &arr_tok_c);
		keyss = jsmnutil_get_array_toks(action, arr_tok_v);
		act_key_len = size = jsmnutil_array_count(action, arr_tok_v);
		t_arr_tok = arr_tok_v+1;
		tmp_action = calloc(1, (size + 1) * sizeof(char *));
		tmp_action[size] = NULL;
		tmp_idx = 0;
		while ((str = json_array_get_one_str(action, &size, &t_arr_tok))) {
			tmp_action[tmp_idx] = str;
			tmp_idx++;
		}
//		if(keyss){
//			jsmnutil_tokv_free(keyss);
//		}
//		if(arr_tok_v){
//			jsmnutil_tokv_free(&arr_tok_v);
//		}
		t_arr_tok = NULL;
		str = NULL;

		subsys = get_json_key_value(match_p, "SUBSYSTEM", tok_v, tok_c);
		vid = get_json_key_value(match_p, "ID_VENDOR_ID", tok_v, tok_c);
		model = get_json_key_value(match_p, "ID_MODEL_ID", tok_v, tok_c);
		DEVNAME = get_json_key_value(match_p, "DEVNAME", tok_v, tok_c);

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

		if(str) {
			free(str);
			str = 0;
		}

		if (tok_v) {
			free(tok_v);
			tok_v = 0;
		}

		append(&device_list->next_match, tmp_action, act_key_len, subsys, vid, model, gid, perm, uid, tmp_devname, key_len);

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
		if(match_p)
		{
			free(match_p);
			match_p = 0;
		}
		if(apply)
		{
			free(apply);
			apply = 0;
		}
		if(action)
		{
			free(action);
			action = 0;
		}
		if(vid)
		{
			free(vid);
			vid = 0;
		}
		if(subsys)
		{
			free(subsys);
			subsys = 0;
		}
		if(model)
		{
			free(model);
			model = 0;
		}
		if(DEVNAME)
		{
			free(DEVNAME);
			DEVNAME = 0;
		}
		if(tmp_devname) {
			free(tmp_devname);
		}
		key_i++;
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

	return &device_list->next_match;
}
