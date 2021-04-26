/*
 * Copyright (c) 2021 Pantacor Ltd.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <jsmn/jsmn.h>
#include <jsmn/jsmnutil.h>
#include "utils.h"
#include "pvhotmap_parser.h"

int tsh_run_io(char *cmd, int wait, int *status,
		int stdin_p[], int stdout_p[], int stderr_p[]) {
	return 0;
}

static int append (struct dl_list *head, char **pv_action, int actkeylen, char *subsys,
		char *vid, char *model, char *gid, char *perm, char *uid, char **dname, int dnamesize) {

	struct _match *tmp_list;
	char call_itr = 0;
	int total_size = 0;

	for(call_itr=0; call_itr<actkeylen; call_itr++) {

		tmp_list = malloc(sizeof(*tmp_list));
		if (tmp_list == NULL)
			return -1;

		tmp_list->action[call_itr] = calloc(1, ((actkeylen + strlen(pv_action[call_itr])) + sizeof(char)));
		strcpy(tmp_list->action[call_itr], "ACTION=");
		strncat(tmp_list->action[call_itr], pv_action[call_itr], ((actkeylen + strlen(pv_action[call_itr])) + sizeof(char)));
		strcpy(tmp_list->subsystem, "SUBSYSTEM=");
		strcat(tmp_list->subsystem, subsys);
		total_size += strlen(pv_action[call_itr]) + strlen(tmp_list->subsystem);

		if(vid) {
			strcpy(tmp_list->vendor_id, "ID_VENDOR_ID=");
			strcat(tmp_list->vendor_id, vid);
			total_size += strlen(tmp_list->vendor_id);
		}
		if(model) {
			strcpy(tmp_list->model_id, "ID_MODEL_ID=");
			strcat(tmp_list->model_id, model);
			total_size += strlen(tmp_list->model_id);
		}
		if(gid) {
			strcpy(tmp_list->apply.gid, "GID=");
			strcat(tmp_list->apply.gid, gid);
			total_size += strlen(tmp_list->apply.gid);
		}
		if(uid) {
			strcpy(tmp_list->apply.uid, "UID=");
			strcat(tmp_list->apply.uid, uid);
			total_size += strlen(tmp_list->apply.uid);
		}
		if(perm) {
			strcpy(tmp_list->apply.perm, "PERM=");
			strcat(tmp_list->apply.perm, perm);
			total_size += strlen(tmp_list->apply.perm);
		}

		tmp_list->devname = calloc(1, (dnamesize+1)*sizeof(char *));
		tmp_list->devname[dnamesize] = NULL;
		tmp_list->devname_size = dnamesize;
		for(int i=0; i<dnamesize; i++) {
			tmp_list->devname[i] = calloc(1, (strlen("DEVNAME=")+strlen(dname[i])));
			strcpy(tmp_list->devname[i], "DEVNAME=");
			strcat(tmp_list->devname[i], dname[i]);
			total_size += strlen(tmp_list->devname[i]);
		}
		dl_list_add_tail(head, &tmp_list->next_match);
	}
	//TODO: free tmp_list;
	return 0;
}

struct dl_list *parse_rules_file(void) {

	FILE *json_fd;
	char *json_content, *key, *um;
	char *match_p, *apply, *action, **tmp_action, *subsys, *vid, *model, *dev_name, **tmp_devname, *str, *perm, *gid, *uid;
	int parse_rv, key_len, act_key_len, tokc, tok_c, arr_tok_c, size, tmp_idx;
	long int json_len;
	size_t rv = 0;
	jsmn_parser p;
	jsmntok_t t[128]; /* We expect no more than 128 tokens */
	jsmntok_t *tokv, *tok_v, *arr_tok_v;
	jsmntok_t **key_i, **keys, **keyss, *t_arr_tok;
	struct _match *device_list;

	json_fd = fopen("devlist.json", "r");
	if(json_fd == NULL) {
		perror("Cannot open file");
		return NULL;
	}
	if(fseek(json_fd, 0L, SEEK_END)) {
		perror("Cannot seek to end\n");
		return NULL;
	}
	json_len = ftell(json_fd);
	printf("Length of Json File: %ld\n", json_len);
	rewind(json_fd);

	json_content = malloc(json_len);
	if(json_content == NULL) {
		perror("Error during malloc\n");
		return NULL;
	}
	rv = fread(json_content, 1, json_len, json_fd);
	if((rv != json_len) || (rv == 0)) {
		perror("Cannot Read from json file\n");
		return NULL;
	}

	jsmn_init(&p);
	parse_rv = jsmn_parse(&p, json_content, json_len, t, sizeof(t)/sizeof(t[0]));
	if (parse_rv < 0) {
		printf("Failed to parse JSON: %d\n", parse_rv);
		return NULL;
	}

	/* Assume the top-level element is an object */
	if (parse_rv < 1 || t[0].type != JSMN_OBJECT) {
		printf("Object expected\n");
		return NULL;
	}
	jsmnutil_parse_json(json_content, &tokv, &tokc);

	/*extract the values of top most key from json rules which is "rules"*/
	um = get_json_key_value(json_content, "rules", tokv, tokc);
	if (!um) {
		goto out;
	}
	if (tokv)
		free(tokv);

	device_list = malloc(sizeof(*device_list));
	if (device_list == NULL)
		goto out;
	dl_list_init(&device_list->next_match);

	/*parse "rules" json array*/
	rv = jsmnutil_parse_json(um, &tokv, &tokc);
	/*get all the tokens inside "rules" json array as jsmn tokens*/
	keys = jsmnutil_get_array_toks(um, tokv);

//	do_lookup_json_key(keys, json_content);


	key_i = keys;
	while (*key_i) {

		/*get length inside rules[] json array, i.e. compute the length of both the match {} rules */
		key_len = (*key_i)->end - (*key_i)->start;

		// copy key
		key = malloc(key_len+1);
		if (!key)
			break;

		/*extract/convert entire json inside rules[] json array to json string for further parsing*/
		snprintf(key, key_len+1, "%s", um+(*key_i)->start);
		/*parse entire json starting from first match: {}*/
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
		perm = get_json_key_value(apply, "perm", tok_v, tok_c);
		gid = get_json_key_value(apply, "gid", tok_v, tok_c);
		uid = get_json_key_value(apply, "uid", tok_v, tok_c);

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
		/*extract all values one by one inside ACTION: [] json array*/
		while ((str = json_array_get_one_str(action, &size, &t_arr_tok))) {
			tmp_action[tmp_idx] = calloc(1, strlen(str));
			strcpy(tmp_action[tmp_idx], str);
			if(str) free(str);
			tmp_idx++;
		}
		t_arr_tok = NULL;
		str = NULL;
		if(arr_tok_v) free(arr_tok_v);

		subsys = get_json_key_value(match_p, "SUBSYSTEM", tok_v, tok_c);
		vid = get_json_key_value(match_p, "ID_VENDOR_ID", tok_v, tok_c);
		model = get_json_key_value(match_p, "ID_MODEL_ID", tok_v, tok_c);
		dev_name = get_json_key_value(match_p, "DEVNAME", tok_v, tok_c);

		if (tok_v) {
			free(tok_v);
			tok_v = 0;
		}
		if (keyss) jsmnutil_tokv_free(keyss);

		rv = jsmnutil_parse_json(dev_name, &tok_v, &tok_c);
		keyss = jsmnutil_get_array_toks(dev_name, tok_v);
		key_len = size = jsmnutil_array_count(dev_name, tok_v);
		t_arr_tok = tok_v+1;
		tmp_devname = calloc(1, (size + 1) * sizeof(char *));
		tmp_devname[size] = NULL;

		tmp_idx = 0;
		/*extract all values one by one inside DEVNAME: [] json array*/
		while ((str = json_array_get_one_str(dev_name, &size, &t_arr_tok))) {
			tmp_devname[tmp_idx] = calloc(1, strlen(str));
			strcpy(tmp_devname[tmp_idx], str);
			if(str) free(str);
			tmp_idx++;
		}

//		if(str) free(str);

		append(&device_list->next_match, tmp_action, act_key_len, subsys, vid, model, gid, perm, uid, tmp_devname, key_len);

		if (key) free(key);
		if(keyss) jsmnutil_tokv_free(keyss);
		if(match_p) free(match_p);
		if(apply) free(apply);
		if(action) free(action);
		if(vid) free(vid);
		if(subsys) free(subsys);
		if(model) free(model);
		if(gid) free(gid);
		if(uid) free(uid);
		if(perm) free(perm);
		if(dev_name) free(dev_name);
		for(int i=0; i<act_key_len; i++) {
			if(tmp_action[i]) free(tmp_action[i]);
		}
		for(int i=0; i<key_len; i++) {
			if(tmp_devname[i]) free(tmp_devname[i]);
		}
		free(tmp_action);
		free(tmp_devname);

		key_i++;
	}
	out:
	if (tokv) free(tokv);
	if (tok_v) free(tok_v);
	if(um) free(um);
	if(keys)jsmnutil_tokv_free(keys);
	if(json_content) free(json_content);

	fclose(json_fd);

//	dump_list(&device_list->next_match);

	return &device_list->next_match;
}
