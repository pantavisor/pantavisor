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
#include "pv_runc_container_status.h"
#include "jsmn.h" // Include jsmn header

#include <stdio.h>
#include <stdlib.h> // For malloc, free, strtol
#include <string.h> // For strncpy, strcmp, strndup

extern void (*__vlog)(char *module, int level, const char *fmt, ...);

#define PV_VLOG __vlog
#define MODULE_NAME "pv_runc_container_status"
#define pv_log(level, msg, ...) __vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

void pv_runc_init_container_state(pv_runc_container_state *state)
{
	if (state) {
		state->pid = 0;
	}
}

void pv_runc_free_container_state(pv_runc_container_state *state)
{
	if (state) {
		state->pid = 0;
	}
}

bool pv_runc_parse_container_state_json(const char *json_string,
					pv_runc_container_state *state)
{
	jsmn_parser parser;
#define _tokchunk_ 128
	int tokc = _tokchunk_;
	jsmntok_t *tokens = NULL;
	int r;

	pv_runc_init_container_state(state);

	jsmn_init(&parser);
again:
	tokens = realloc(tokens, tokc * sizeof(jsmntok_t));
	r = jsmn_parse(&parser, json_string, strlen(json_string), tokens, tokc);

	if (r < 0) {
		if (r == JSMN_ERROR_NOMEM) {
			tokc += _tokchunk_;
			goto again;
		}
		pv_log(WARN, "Failed to parse JSON: %d: %s", r, json_string);
		return false;
	}

	// Expect the root to be an object
	if (r < 1 || tokens[0].type != JSMN_OBJECT) {
		pv_log(WARN, "JSON is not an object.");
		return false;
	}

	for (int i = 0; i < r; i++) {
		if (tokens[i].type == JSMN_STRING &&
		    tokens[i].size ==
			    1) { // Check for a key (string with one child)
			// Check if the current token is the "xxxx" key
			if (strncmp(json_string + tokens[i].start,
				    "init_process_pid",
				    tokens[i].end - tokens[i].start) == 0) {
				// The next token should be the value
				if (i + 1 < r) {
					jsmntok_t value_token = tokens[i + 1];
					if (value_token.type ==
					    JSMN_PRIMITIVE) { // JSMN_PRIMITIVE handles numbers, booleans, null
						char *value_str = (char *)malloc(
							value_token.end -
							value_token.start + 1);
						if (value_str) {
							strncpy(value_str,
								json_string +
									value_token
										.start,
								value_token.end -
									value_token
										.start);
							value_str[value_token
									  .end -
								  value_token
									  .start] =
								'\0';

							state->pid = atoll(
								value_str);

							free(value_str);
							break;
						}
					}
				}
			}
			i += tokens[i + 1].size;
		}
	}

	free(tokens);

	// Basic validation: Check if required fields are present (optional but good practice)
	if (!state->pid) {
		pv_log(WARN,
		       "Missing required fields (init_process_pid) in JSON.\n");
		pv_runc_free_container_state(
			state); // Clean up partially parsed data
		return false;
	}

	return true;
}

char *pv_runc_read_file_to_string(const char *filepath)
{
	FILE *fp = NULL;
	long file_size;
	char *buffer = NULL;

	fp = fopen(filepath,
		   "rb"); // Open in binary mode for cross-platform
	if (fp == NULL) {
		perror("Error opening file");
		return NULL;
	}

	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	rewind(fp);

	buffer = (char *)malloc(file_size + 1); // +1 for null terminator
	if (buffer == NULL) {
		perror("Error allocating buffer");
		fclose(fp);
		return NULL;
	}

	size_t bytes_read = fread(buffer, 1, file_size, fp);
	if (bytes_read != (size_t)file_size) {
		pv_log(WARN,
		       "Error reading file: read %zu bytes, expected %ld\n",
		       bytes_read, file_size);
		free(buffer);
		fclose(fp);
		return NULL;
	}
	buffer[file_size] = '\0'; // Null-terminate the string

	pv_log(WARN, "read file: %zu bytes\n", bytes_read);
	pv_log(WARN, "read file buffer: %s\n", buffer);

	fclose(fp);
	return buffer;
}

bool pv_runc_parse_container_state_file(const char *filepath,
					pv_runc_container_state *state)
{
	char *json_content = pv_runc_read_file_to_string(filepath);
	if (json_content == NULL) {
		// pv_runc_read_file_to_string already printed an error
		return false;
	}

	bool success = pv_runc_parse_container_state_json(json_content, state);

	pv_log(WARN, "parsed state with pid: %d", state->pid);

	free(json_content); // Always free the buffer read from the file
	return success;
}
