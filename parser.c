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

static int parse_systemc(struct sc_state *s, char *buf, int n)
{
	int i, c;
	int ret, tokc, size;
	char *str;
	jsmntok_t *tokv;
	jsmntok_t **key;

	ret = jsmnutil_parse_json(buf, &tokv, &tokc);
	s->kernel = get_json_key_value(buf, "linux", tokv, tokc);

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
	if (!this)
		goto out;

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
	printf("configs=%d\n", size);
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
	printf("shares=%d\n", size);
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

struct sc_state* sc_parse_state(struct systemc *sc, char *buf, int size)
{
	int tokc, ret, count, n;
	char *key, *value, *ext = 0;
	jsmntok_t *tokv;
	jsmntok_t **k;

	struct sc_state *this = calloc(1, sizeof(struct sc_state));

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
	printf("\n\nkernel: '%s'\n", this->kernel);
	char **initrd = this->initrd;
	printf("initrd: \n");
	while (*initrd) {
		printf("  '%s'\n", *initrd);
		initrd++;
	}
	struct sc_platform *p = this->platforms;
	printf("platform: '%s'\n", p->name);
	while (p) {
		printf("  type: '%s'\n", p->type);
		printf("  exec: '%s'\n", p->exec);
		printf("  configs:\n");
		char **config = p->configs;
		while (*config) {
			printf("    '%s'\n", *config);
			config++;
		}
		printf("  shares: 0x%08lx\n", p->ns_share);
		p = p->next;
	}
	struct sc_volume *v = this->volumes;
	while (v) {
		printf("volume: '%s'\n", v->name);
		v = v->next;
	}
	struct sc_object *o = this->objects;
	while (o) {
		printf("object: \n");
		printf("  name: '%s'\n", o->name);
		printf("  name: '%s'\n", o->id);
		o = o->next;
	}

	return this;
}
