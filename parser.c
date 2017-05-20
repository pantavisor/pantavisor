/*
 * Copyright (c) 2017 Pantacor Ltd.
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
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_NAME             "parser"
#define sc_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "utils.h"
#include "platforms.h"
#include "volumes.h"
#include "objects.h"
#include "systemc.h"

#define SC_NS_NETWORK	0x1
#define SC_NS_UTS	0x2
#define SC_NS_IPC	0x4

typedef struct ns_share_t { char *name; unsigned long val; } ns_share_t;
ns_share_t ns_share[] = {
	{ "NETWORK", SC_NS_NETWORK },
	{ "UTS", SC_NS_UTS },
	{ "IPC", SC_NS_IPC },
	{ NULL, 0xff }
};

static unsigned long ns_share_flag(char *key)
{
	for (ns_share_t *ns = ns_share; ns->name != NULL; ns++) {
		if (!strcmp(ns->name, key))
			return ns->val;
	}

	return 0;
}

static int parse_systemc(struct sc_state *s, char *value, int n)
{
	int i, c;
	int ret, tokc, size;
	char *str, *buf;
	jsmntok_t *tokv;
	jsmntok_t **key;

	// take null terminate copy of item to parse
	buf = calloc(1, (n+1) * sizeof(char));
	buf = strncpy(buf, value, n);

	ret = jsmnutil_parse_json(buf, &tokv, &tokc);
	s->kernel = get_json_key_value(buf, "linux", tokv, tokc);
	s->firmware = get_json_key_value(buf, "firmware", tokv, tokc);

	// get initrd components
	key = jsmnutil_get_object_keys(buf, tokv);
	while (*key) {
		c = (*key)->end - (*key)->start;
		if (strncmp("initrd", buf+(*key)->start, strlen("initrd"))) {
			key++;
			continue;
		}

		// parse array data
		i = 0;
		jsmntok_t *k = (*key+2);
		size = (*key+1)->size;
		s->initrd = calloc(1, (size+1) * sizeof(char*));
		s->initrd[size] = NULL;
		while ((str = json_array_get_one_str(buf, &size, &k))) {
			s->initrd[i] = str;
			i++;
		}

		break;
	}

	// get platforms and create empty items
	key = jsmnutil_get_object_keys(buf, tokv);
	while (*key) {
		c = (*key)->end - (*key)->start;
		if (strncmp("platforms", buf+(*key)->start, strlen("platforms"))) {
			key++;
			continue;
		}

		// parse array data
		jsmntok_t *k = (*key+2);
		size = (*key+1)->size;
		while ((str = json_array_get_one_str(buf, &size, &k)))
			sc_platform_add(s, str);

		break;
	}

	// get volumes and create empty items
	key = jsmnutil_get_object_keys(buf, tokv);
	while (*key) {
		c = (*key)->end - (*key)->start; 
		if (strncmp("volumes", buf+(*key)->start, strlen("volumes"))) {
			key++;
			continue;
		}

		// parse array data
		jsmntok_t *k = (*key+2);
		size = (*key+1)->size;
		while ((str = json_array_get_one_str(buf, &size, &k)))
			sc_volume_add(s, str);

		break;
	}

	if (tokv)
		free(tokv);
	if (buf)
		free(buf);

	return 1;
}

static int parse_platform(struct sc_state *s, char *buf, int n)
{
	int i;
	int tokc, ret, size;
	jsmntok_t *tokv, *t;
	char *name, *str;
	char *configs, *shares;
	struct sc_platform *this;

	ret = jsmnutil_parse_json(buf, &tokv, &tokc);
	name = get_json_key_value(buf, "name", tokv, tokc);

	this = sc_platform_get_by_name(s, name);
	if (!this) {
		sc_log(ERROR, "");
		goto out;
	}

	this->type = get_json_key_value(buf, "type", tokv, tokc);
	this->exec = get_json_key_value(buf, "exec", tokv, tokc);

	configs = get_json_key_value(buf, "configs", tokv, tokc);
	shares = get_json_key_value(buf, "share", tokv, tokc);

	// free intermediates
	if (name) {
		free(name);
		name = 0;
	}
	if (tokv) {
		free(tokv);
		tokv = 0;
	}

	ret = jsmnutil_parse_json(configs, &tokv, &tokc);
	size = jsmnutil_array_count(buf, tokv);
	t = tokv+1;
	this->configs = calloc(1, (size + 1) * sizeof(char *));
	this->configs[size] = NULL;
	i = 0;
	while ((str = json_array_get_one_str(configs, &size, &t))) {
		this->configs[i] = str;
		i++;
	}

	// free intermediates
	if (configs) {
		free(configs);
		configs = 0;
	}
	if (tokv) {
		free(tokv);
		tokv = 0;
	}

	ret = jsmnutil_parse_json(shares, &tokv, &tokc);
	size = jsmnutil_array_count(shares, tokv);
	t = tokv+1;
	this->ns_share = 0;
	while ((str = json_array_get_one_str(shares, &size, &t))) {
		this->ns_share |= ns_share_flag(str);
		i++;
	}

	// free intermediates
	if (shares) {
		free(shares);
		configs = 0;
	}
	if (tokv) {
		free(tokv);
		tokv = 0;
	}

	this->done = true;

out:
	if (name)
		free(name);
	if (tokv)
		free(tokv);

	return 0;
}

void sc_state_free(struct sc_state *this)
{
	char **initrd = this->initrd;
	while (initrd && *initrd) {
		free(*initrd);
		initrd++;
	}
	struct sc_platform *pt, *p = this->platforms;
	while (p) {
		free(p->type);
		free(p->exec);
		char **config = p->configs;
		while (config && *config) {
			free(*config);
			config++;
		}
		pt = p;
		p = p->next;
		free(pt);
	}
	struct sc_volume *vt, *v = this->volumes;
	while (v) {
		free(v->name);
		vt = v;
		v = v->next;
		free(vt);
	}
	struct sc_object *ot, *o = this->objects;
	while (o) {
		free(o->name);
		free(o->id);
		free(o->relpath);
		free(o->geturl);
		free(o->objpath);
		ot = o;
		o = o->next;
		free(ot);
	}
}

struct sc_state* sc_parse_state(struct systemc *sc, char *buf, int size, int rev)
{
	int tokc, ret, count, n;
	char *key, *value, *ext = 0;
	jsmntok_t *tokv;
	jsmntok_t **k;

	struct sc_state *this = calloc(1, sizeof(struct sc_state));

	// set rev
	this->rev = rev;

	// Parse full state json
	ret = jsmnutil_parse_json(buf, &tokv, &tokc);

	count = json_get_key_count(buf, "systemc.json", tokv, tokc);
	if (!count || (count > 1)) {
		printf("Invalid systemc.json count in state");
		return NULL;
	}

	value = get_json_key_value(buf, "systemc.json", tokv, tokc);
	if (!value) {
		printf("Unable to get systemc.json value from state");
		return NULL;
	}

	if (!parse_systemc(this, value, strlen(value)))
		return NULL;

	k = jsmnutil_get_object_keys(buf, tokv);

	// platform head is sc->state->platforms
	while (*k) {
		n = (*k)->end - (*k)->start;

		// avoid systemc.json and #spec special keys
		if (!strncmp("systemc.json", buf+(*k)->start, n) ||
		    !strncmp("#spec", buf+(*k)->start, n)) {
			k++;
			continue;
		}

		// copy key
		key = malloc(n+1);
		snprintf(key, n+1, "%s", buf+(*k)->start);

		// copy value
		n = (*k+1)->end - (*k+1)->start;
		value = malloc(n+1);
		snprintf(value, n+1, "%s", buf+(*k+1)->start);

		// check extension in case of file (json=platform, other=file)
		ext = strrchr(key, '.');
		if (ext && !strcmp(ext, ".json"))
			parse_platform(this, value, strlen(value));
		else
			sc_objects_add(this, key, value, sc->config->storage.mntpoint);

		// free intermediates
		if (key)
			free(key);
		if (value)
			free(value);
		k++;
	}

	// copy buffer
	this->json = strdup(buf);

	// print
	sc_log(INFO, "kernel: '%s'\n", this->kernel);
	char **initrd = this->initrd;
	sc_log(INFO, "initrd: \n");
	while (*initrd) {
		sc_log(INFO, "  '%s'\n", *initrd);
		initrd++;
	}
	struct sc_platform *p = this->platforms;
	sc_log(INFO, "platform: '%s'\n", p->name);
	while (p) {
		sc_log(INFO, "  type: '%s'\n", p->type);
		sc_log(INFO, "  exec: '%s'\n", p->exec);
		sc_log(INFO, "  configs:\n");
		char **config = p->configs;
		while (config && *config) {
			sc_log(INFO, "    '%s'\n", *config);
			config++;
		}
		sc_log(INFO, "  shares: 0x%08lx\n", p->ns_share);
		p = p->next;
	}
	struct sc_volume *v = this->volumes;
	while (v) {
		sc_log(INFO, "volume: '%s'\n", v->name);
		v = v->next;
	}
	struct sc_object *o = this->objects;
	while (o) {
		sc_log(INFO, "object: \n");
		sc_log(INFO, "  name: '%s'\n", o->name);
		sc_log(INFO, "  name: '%s'\n", o->id);
		o = o->next;
	}

	// remove platforms that have no loaded data
	sc_platforms_remove_not_done(this);

	return this;
}
