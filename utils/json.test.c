
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "json.h"

// a lookup for "status_goal" must not match a longer key sharing its prefix
static void test_get_value_toplevel_exact_match(void)
{
	const char *buf = "{\"status_goal_timeout\":\"30\"}";
	jsmntok_t *tokv;
	int tokc;

	assert(jsmnutil_parse_json(buf, &tokv, &tokc) > 0);
	assert(pv_json_get_value_toplevel(buf, "status_goal", tokv, tokc) ==
	       NULL);

	free(tokv);
	printf("PASS: get_value_toplevel exact key match\n");
}

// a "disks" key nested inside a disks_v3 entry must not satisfy a top-level "disks" lookup
static void test_get_value_toplevel_ignores_nested_key(void)
{
	const char *buf =
		"{\"disks_v3\":[{\"type\":\"dual\",\"disks\":[\"a\",\"b\"]}]}";
	jsmntok_t *tokv;
	int tokc;

	assert(jsmnutil_parse_json(buf, &tokv, &tokc) > 0);
	assert(pv_json_get_value_toplevel(buf, "disks", tokv, tokc) == NULL);

	free(tokv);
	printf("PASS: get_value_toplevel ignores a nested key\n");
}

static void test_get_value_toplevel_finds_top_level_key(void)
{
	const char *buf = "{\"name\":\"foo\",\"nested\":{\"name\":\"bar\"}}";
	jsmntok_t *tokv;
	int tokc;
	char *val;

	assert(jsmnutil_parse_json(buf, &tokv, &tokc) > 0);
	val = pv_json_get_value_toplevel(buf, "name", tokv, tokc);
	assert(val != NULL);
	assert(strcmp(val, "foo") == 0);

	free(val);
	free(tokv);
	printf("PASS: get_value_toplevel finds the top-level key, not the nested one\n");
}

// the array walker must skip an element's whole subtree, not just one token,
// or it desyncs on the next entry once a value (here "b") is an object
static void test_array_elem_next_skips_nested_value(void)
{
	const char *buf = "[{\"a\":1,\"b\":{\"c\":2,\"d\":3}},{\"a\":4}]";
	jsmntok_t *tokv, *tok_end, *t, *next;
	int tokc, el_end;
	char *elem2;

	assert(jsmnutil_parse_json(buf, &tokv, &tokc) > 0);
	tok_end = tokv + tokc;
	t = tokv + 1; // first array element
	el_end = t->end;

	next = pv_json_array_elem_next(t, tok_end, el_end);
	assert(next < tok_end);
	assert(next->start >= el_end);

	elem2 = pv_json_get_one_str(buf, &next);
	assert(elem2 != NULL);
	assert(strcmp(elem2, "{\"a\":4}") == 0);

	free(elem2);
	free(tokv);
	printf("PASS: array_elem_next skips a nested object value\n");
}

int main()
{
	test_get_value_toplevel_exact_match();
	test_get_value_toplevel_ignores_nested_key();
	test_get_value_toplevel_finds_top_level_key();
	test_array_elem_next_skips_nested_value();

	struct pv_json_ser js;

	pv_json_ser_init(&js, 16);

	pv_json_ser_object(&js);
	{
		pv_json_ser_key(&js, "one_key_thingy");
		pv_json_ser_string(&js, "this will trigger a buf resize");

		pv_json_ser_object_pop(&js);
	}

	char *buf = pv_json_ser_str(&js);

	printf("buf: %s\n", buf);

	free(buf);

	return 0;
}
