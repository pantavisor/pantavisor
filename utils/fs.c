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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/limits.h>

#include "fs.h"

bool dir_exist(const char *dir)
{
	bool exists = false;

	DIR* tmp = opendir(dir);
	if (tmp) {
		exists = true;
		closedir(tmp);
	}

	return exists;
}

int mkdir_p(char *dir, mode_t mode)
{
	const char *tmp = dir;
	const char *orig = dir;
	char *makeme;

	do {
		dir = (char*)tmp + strspn(tmp, "/");
		tmp = dir + strcspn(dir, "/");
		makeme = strndup(orig, dir - orig);
		if (*makeme) {
			if (mkdir(makeme, mode) && errno != EEXIST) {
				free(makeme);
				return -1;
			}
		}
		free(makeme);
	} while(tmp != dir);

	return 0;
}

void syncdir(char *file)
{
	int fd;
	char *dir;

	if (!file)
		return;

	dir = strdup(file);
	dirname(dir);

	fd = open(dir, O_RDONLY);
	if (fd >= 0) {
		fsync(fd);
		close(fd);
	}

	if (dir)
		free(dir);
}

int remove_at(char *path, char *filename)
{
	char full_path[PATH_MAX];

	sprintf(full_path, "%s/%s", path, filename);
	return remove(full_path);
}

int remove_in(char *path, char *dirname)
{
	int n = 0;
	struct dirent **d;
	char full_path[512];

	sprintf(full_path, "%s/%s/", path, dirname);
	n = scandir(full_path, &d, NULL, alphasort);

	if (n < 0) {
		goto out;
	}

	while (n--) {
		// discard . and .. from scandir
		if (!strcmp(d[n]->d_name, ".") || !strcmp(d[n]->d_name, ".."))
			continue;
		// first try to remove it as a file
		if (remove_at(full_path, d[n]->d_name))
			// remove it as a dir if not a file
			remove_in(full_path, d[n]->d_name);
		free(d[n]);
	}
	free(d);

	remove(full_path);

out:
	return n;
}
