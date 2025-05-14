#include "pvtx_jsmn_utils.h"

#include <stdlib.h>

jsmntok_t *pv_pvtx_jsmn_parse_data(const char *json, size_t json_len, int *len)
{
	jsmn_parser parser;
	jsmn_init(&parser);

	int tkn_len = jsmn_parse(&parser, json, json_len, NULL, 0);
	jsmntok_t *tkn = calloc(tkn_len, sizeof(jsmntok_t));
	if (!tkn) {
		if (len)
			*len = 0;
		return NULL;
	}

	jsmn_init(&parser);
	tkn_len = jsmn_parse(&parser, json, json_len, tkn, tkn_len);

	if (len)
		*len = tkn_len;
	return tkn;
}

bool pv_pvtx_jsmn_is_key(const char *data, jsmntok_t *tkn)
{
	const char *p = data + tkn->end;

	while (*p != ':' && *p != '\0' && *p != ',')
		p++;

	return *p == ':';
}