#ifndef TEMPLATE_ENGINE_H
#define TEMPLATE_ENGINE_H

#include <stdio.h>

typedef struct {
    char *key;
    char *value;
} pair;

void append(char **str, char *add);

void decode(char *url);

void err(char *file, int line, void *heap_obj, int exit_prog);

long int f_size(FILE * file);

int num_char_occurences(const char *str, char c);

int num_digits(int num);

void remove_spaces_btwn(char *s);

char *rendered_template(const char *html_buf, int param_count, pair *params);

char *search_keys_val_in(const char *key, int param_count, pair *params);

#endif
