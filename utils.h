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
#ifndef PV_UTILS_H
#define PV_UTILS_H

#include <sys/types.h>

#include <jsmn/jsmnutil.h>
#include <stdlib.h>

int mkdir_p(char *dir, mode_t mode);

void syncdir(char *dir);
char *rand_string(int size);
int traverse_token (char *buf, jsmntok_t* tok, int t);
int get_digit_count(int number);
int get_json_key_value_int(char *buf, char *key, jsmntok_t* tok, int tokc);
char* get_json_key_value(char *buf, char *key, jsmntok_t* tok, int tokc);
char* json_array_get_one_str(char *buf, int *n, jsmntok_t **tok);
int json_get_key_count(char *buf, char *key, jsmntok_t *tok, int tokc);
char *unescape_str_to_ascii(char *buf, char *code, char c);
char *skip_prefix(char *str, const char *key);
char* json_get_one_str(char *buf, jsmntok_t **tok);
char* format_json(char *buf, int len);
char *str_replace(char *str, int len, char which, char what);
int get_endian(void);
int get_dt_model(char *buf, int buflen);
int get_cpu_model(char *buf, int buflen);

#ifndef ARRAY_LEN
#define ARRAY_LEN(X) 	(ssize_t)(sizeof(X)/sizeof(X[0]))
#endif /* ARRAY_LEN*/

#ifndef free_member
#define free_member(ptr, member)\
({\
 if (ptr->member)\
	free((void*)(ptr->member));\
 ptr->member = NULL;\
})
#endif /* free_member */

#ifdef __arm__
#define PV_ARCH		"arm"
#elif __x86_64__
#define PV_ARCH		"x86_64"
#elif __mips__
#define	PV_ARCH		"mips"
#else
#define PV_ARCH		"unknown"
#endif

#if UINTPTR_MAX == 0xffffffff
#define	PV_BITS		"32"
#else
#define	PV_BITS		"64"
#endif

/*
 * Returns 0 on success.
 * For setting, value holds a null terminated string.
 * For get, the value is returned back in dst.
 */
int set_xattr_on_file(const char *filename, char *attr, char *value);
int get_xattr_on_file(const char *filename, char *attr, char **dst, int (*alloc)(char **, int));
ssize_t write_nointr(int fd, char *buf, ssize_t len);
ssize_t read_nointr(int fd, char *buf, ssize_t len);
int lock_file(int fd);
/*
 * Returns the file descriptor on success.
 */
int open_and_lock_file(const char *fname, int flags, mode_t mode);
int unlock_file(int fd);
int gzip_file(const char *filename, const char *target_name);
int check_and_open_file(const char *fname, int flags, mode_t mode);

#define PREFIX_MODEL	"model name\t:"
#endif // PV_UTILS_H
