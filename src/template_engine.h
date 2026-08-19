#ifndef TEMPLATE_ENGINE_H
#define TEMPLATE_ENGINE_H

#include <stdio.h>

typedef struct {
    char *key;
    char *value;
} pair;

int append(char *str, const char *add, int new_total_size);

int heap_append(char **str, const char *add, int new_total_size);

int decode(char *url);

void err(const char *file, const int line, void *heap_obj, const int exit_prog);

long int f_size(FILE * file);

int key_exists_in_arr_pairs(const char *key, const int param_count, const pair *params);

int num_digits(int num);

void remove_spaces_btwn(char *s);

char *rendered_template(const char *html_buf, int param_count, pair *params);

int safely_update_into_arr_pair(const char *key, const char *val, int *len_ptr, pair *params, const int override_existing);

char *search_keys_val_in(const char *key, int param_count, pair *params);

#endif
