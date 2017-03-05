#ifndef SC_UTILS_H
#define SC_UTILS_H

#include <sys/types.h>

#include <jsmn/jsmnutil.h>

int mkdir_p(const char *dir, mode_t mode);

char *rand_string(int size);
int traverse_token (char *buf, jsmntok_t* tok, int t);
int get_digit_count(int number);
int get_json_key_value_int(char *buf, char *key, jsmntok_t* tok, int tokc);
char* get_json_key_value(char *buf, char *key, jsmntok_t* tok, int tokc);
char* json_array_get_one_str(char *buf, int *n, jsmntok_t **tok);
int json_get_key_count(char *buf, char *key, jsmntok_t *tok, int tokc);

#endif
