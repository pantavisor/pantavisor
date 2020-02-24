/*
 * Copyright (c) 2020 Pantacor Ltd.
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
#include "parser_bundle.h"
#define MODULE_NAME 	"cmd-json-log"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"
#include "cmd_json_log.h"

static int do_level_action(struct json_key_action *jka, char *value)
{
	int *level = (int*)jka->opaque;

	*level = -1;
	sscanf(value, "%d", level);
	switch (*level) {
		case FATAL:
		case ERROR:
		case WARN:
		case INFO:
		case DEBUG:
		case ALL:
			break;
		default:
			*level = DEBUG;
	}
	return 0;
}

int push_cmd_json_log(char *json_buf)
{
	char *src = NULL;
	char *msg = NULL;
	int level = -1;
	int ret = 0;

	struct json_key_action cmd_json [] = {
		ADD_JKA_ENTRY(JSON_ATTR_SOURCE, JSMN_STRING, &src, NULL, true),
		ADD_JKA_ENTRY(JSON_ATTR_LEVEL, JSMN_STRING, &level, do_level_action, false),
		ADD_JKA_ENTRY(JSON_ATTR_MSG, JSMN_STRING, &msg, NULL, true),
		ADD_JKA_NULL_ENTRY()
	};

	ret = start_json_parsing_with_action(json_buf, cmd_json, JSMN_OBJECT);
	if (ret == 0) {
		if (msg && src && (level >= 0))
			__log(src, level, "%s", msg);
	}
	if (msg)
		free(msg);
	if (src)
		free(src);
	return ret;
}
