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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MODULE_NAME "buildinfo"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#include "version.h"

#define MAX_BUILD_INFO_FILE_SIZE (64 * 1024) // 64KB

int pv_buildinfo_load_yocto_manifest(void)
{
	FILE *fp;
	long file_size;
	char *buffer;
	int ret = 0; // Initialize return value to success

	fp = fopen("/etc/build", "r");
	if (fp == NULL) {
		pv_log(WARN, "Error opening /etc/build.");
		return -1; // Return -1 for file open error
	}

	// Get the file size
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (file_size > MAX_BUILD_INFO_FILE_SIZE) {
		pv_log(WARN, "File too large (/etc/build). Max: %d",
		       MAX_BUILD_INFO_FILE_SIZE);
		fclose(fp);
		return -4; // Return -4 for file too large error
	}

	// Allocate buffer for the file content + null terminator
	buffer = (char *)malloc(file_size + 1);
	if (buffer == NULL) {
		pv_log(WARN, "Error allocating memory for manifest.");
		fclose(fp);
		return -2; // Return -2 for memory allocation error
	}

	// Read the entire file into the buffer
	if (fread(buffer, 1, file_size, fp) != file_size) {
		pv_log(WARN, "Error reading the entire file.");
		free(buffer);
		fclose(fp);
		return -3; // Return -3 for file read error
	}

	// Null-terminate the buffer
	buffer[file_size] = '\0';

	// Set the global variable
	pv_build_manifest = buffer;

	fclose(fp);
	return ret; // Return 0 for success
}
