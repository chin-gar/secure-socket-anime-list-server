#include <json-c/json.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_types.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "template_engine.h"

typedef enum {
    TEXT,
    VAR,
    IF,
    ELSE,
    ENDIF,
    FOR,
    ENDFOR,
    EXTENDS,
    BLOCK,
    ENDBLOCK
} TType;

typedef struct {
    TType type;
    char *content;
} token;

typedef struct node {
    TType type;
    char *content;
    struct node **children;
    struct node **sec_children; // Only to store IF children when ELSE

    size_t num_children;
    size_t num_sec_children;
} node;

typedef struct stack_node {
    node *node;
    struct stack_node *next;
} stack_node;

void free_node_tree(node *root) {
    if (root->content) free(root->content);
    if (root->children) {
        for (int i = 0, n = root->num_children; i < n; i++) {
            free_node_tree(root->children[i]);
        }
    }
    if (root->type == IF && root->num_sec_children > 0) {
        for (int i = 0, n = root->num_sec_children; i < n; i++) {
            if (root->sec_children[i]) free_node_tree(root->sec_children[i]);
        }
    }
    free(root);
}

void free_stack(stack_node *stack) {
    while (stack != NULL) {
        stack_node *tmp = stack->next;
        free(stack);
        stack = tmp;
    }
}

// TODO: Int status code? Also start reading only reading one char at a time?
void decode(char *url) {
    char backup[strlen(url) + 1];
    strcpy(backup, url);
    for (int i = 0, n = strlen(url); i < n; i++) if (url[i] == '+') url[i] = ' ';
    for (int i = 0, n = num_char_occurences(url, '%'); i < n; i++) {
        int sub = strchr(url, '%') - url;
        char hex[3], *end;
        strncpy(hex, url + sub + 1, 2);
        hex[2] = '\0';
        int decoded = strtol(hex, &end, 16);
        if (*end != '\0' || end == hex || strlen(hex) < 2) {
            continue;
        }

        char *first = strndup(url, sub);
        char *last = strndup(url + sub + 3, strlen(url) - sub + 1);
        if (first == NULL || last == NULL) {
            if (first) free(first);
            if (last) free(last);
            strcpy(url, backup);
            return;
        }

        sprintf(url, "%s%c%s", first, decoded, last);
        free(first);
        free(last);
    }
}

long int f_size(FILE * file) {
    long int orig_pos = ftell(file);
    fseek(file, 0L, SEEK_END);
    long int s = ftell(file);
    fseek(file, 0L, orig_pos);
    return s;
}

int num_char_occurences(const char *str, char c) {
    int count = 0;
    for (int i = 0, n = strlen(str); i < n; i++) if (str[i] == c) count++;
    return count;
}

int num_digits(int num) {
    int digits = 0;
    while (num > 0) {
        digits++;
        num /= 10;
    }
    return digits > 1 ? digits : 1;
}


void err(char *file, int line, void *heap_obj, int exit_prog) {
    if (heap_obj) free(heap_obj);
    char msg[strlen(file) + num_digits(line) + 1];
    sprintf(msg, "%s:%i", file, line);
    perror(msg);
    if (exit_prog > 0) exit(EXIT_FAILURE);
}

char *sanitize(const char *str) {
    char *clean = malloc(1);
    if (clean == NULL) {
        err(__FILE__, __LINE__, NULL, 0);
        return NULL;
    }
    clean[0] = '\0';
    for (int i = 0, n = strlen(str); i < n; i++) {
        switch (str[i]) {
            case '\0':
                continue;
            default:
                clean = realloc(clean, strlen(clean) + 3 + num_digits(str[i]) + 1);
                if (clean == NULL) {
                    err(__FILE__, __LINE__, clean, 0);
                    return NULL;
                }
                if (str[i] >= 0)
                    sprintf(clean, "%s&#%i;", clean, str[i]);
                else sprintf(clean, "%s%c", clean, str[i]);
        }
    }
    return clean;
}

// NOTE: end = exclusive
int len_btwn(const char *str, const char *end) {
    const char *s = strstr(str, end);
    return strlen(str) - strlen(s ? s : "");
}

// NOTE: Uses linear search --> O(n), must be freed
char *search_keys_val_in(const char *key, int param_count, pair *params) {
    for (int i = 0; i < param_count; i++) {
        if (params[i].key && strcmp(params[i].key, key) == 0) {
            char *val = strdup(params[i].value);
            if (val == NULL) {
                err(__FILE__, __LINE__, val, 0);
                break;
            }
            return val;
        }
    }
    return NULL;
}

// TODO: Determine where global vars like these go (only for organization)
node **blocks;
int num_blocks = 0;

void create_token(token **list, TType type, char *built, int *nth) {
    token *temp = realloc(*list, (*nth + 1) * sizeof(token));
    if (temp == NULL) {
        free(temp);
        return;
    }
    temp[*nth].type = type;
    temp[*nth].content = built ? strdup(built) : NULL;
    if (built != NULL) {
        built = realloc(built, 1);
        if (built == NULL) {
            free(temp);
            err(__FILE__, __LINE__, built, 0);
            return;
        }
        built[0] = '\0';
    }
    *list = temp;

    (*nth)++;
}

void free_token_list(token *list, int size) {
    for (int i = 0, n = size; i < n; i++) {
        if (list[i].content && list[i].content != NULL) free(list[i].content);
    }
    free(list);
}

// NOTE: Uses linear search --> O(n)
node *get_block(const char *var) {
    for (int i = 0; i < num_blocks; i++) {
        if (strcmp(blocks[i]->content, var) == 0) return blocks[i];
    }
    return NULL;
}

void append(char **str, char *add) {
    char *temp = realloc(*str, strlen(*str) + strlen(add) + 1);
    if (temp == NULL) {
        err(__FILE__, __LINE__, temp, 0);
        return;
    }
    sprintf(temp, "%s%s", temp, add);
    *str = temp;
}

void remove_spaces_btwn(char *s) { // NOTE: Only works for heap strs
    int i = 0;
    char *str = strdup(s);
    if (str == NULL) {
        err(__FILE__, __LINE__, NULL, 0);
        return;
    }
    while (str[i] == ' ' || str[strlen(str) - i - 1] == ' ') {
        if (str[i] == ' ') {
            char *leading_temp = strndup(&str[i + 1], strlen(str));
            if (leading_temp == NULL) {
                err(__FILE__, __LINE__, leading_temp, 0);
                return;
            }
            str = leading_temp;
            i--;
        }

        if (str[strlen(str) - i - 1] == ' ') {
            char *end_temp = strndup(str, strlen(str) - 1);
            if (end_temp == NULL) {
                err(__FILE__, __LINE__, end_temp, 0);
                return;
            }
            str = end_temp;
        }
        i++;
    }
    s = str;
}

void remove_quotes_btwn(char **s) { // NOTE: Only works for heap strs, only beginning/ending quotes if present
    int i = 0;
    char *str = strdup(*s);
    if (str == NULL) {
        err(__FILE__, __LINE__, NULL, 0);
        return;
    }
    //while (str[i] == '\"' || str[strlen(str) - i - 1] == '\"') {
        if (str[i] == '\"') {
            char *leading_temp = strndup(&str[i + 1], strlen(str));
            if (leading_temp == NULL) {
                err(__FILE__, __LINE__, leading_temp, 0);
                return;
            }
            str = leading_temp;
            //i--;
        }

        if (str[strlen(str) - i - 1] == '\"') {
            char *end_temp = strndup(str, strlen(str) - 1);
            if (end_temp == NULL) {
                err(__FILE__, __LINE__, end_temp, 0);
                return;
            }
            str = end_temp;
        }
        //i++;
    //}
    *s = str;
}

// TODO: Deprecate bc only used to get obj collection for FOR nodes
void *get_json_obj(const char *q, int param_count, pair *params) {
    if (q == NULL) return NULL;
    int dot_len = len_btwn(q, ".");
    int brack_len = len_btwn(q, "[");
    int index = dot_len < brack_len ? dot_len : brack_len;
    int has_at_least_one_sep = index > 0;

    int n = strlen(q);
    int index_inc = (has_at_least_one_sep < 1 ? 0 : index == dot_len ? 1 : 2);
    char *root = strndup(q, has_at_least_one_sep >= 1 ? index : n);
    if (root == NULL) {
        err(__FILE__, __LINE__, NULL, 0);
        return NULL;
    }
    index += index_inc;

    char *json_str = search_keys_val_in(root, param_count, params);

    if (json_str == NULL) {
        free(root);
        return NULL;
    }
    void *obj = json_tokener_parse(json_str);
    if (obj != NULL && index > 0) {
        char *btwn = malloc(1);
        if (btwn == NULL) {
            free(root);
            err(__FILE__, __LINE__, json_str, 0);
            json_object_put(obj);
            return NULL;
        }
        btwn[0] = '\0';
        while (index < n + 1) {
            int inc = strncmp(&q[index], "[\"", 2) == 0 || strncmp(&q[index], "\"]", 2) == 0 ? 2 : strncmp(&q[index], ".", 1) == 0 || strncmp(&q[index], "[", 1) == 0 || strncmp(&q[index], "]", 1) == 0 || index >= n ? 1 : 0;
            if (inc > 0) {
                char *end;
                float num = strtod(btwn, &end);

                struct json_object *tmp_obj;
                if (btwn != end && *end == '\0') {
                    tmp_obj = json_object_array_get_idx(obj, num);
                } else if (json_object_object_get_ex(obj, btwn, &tmp_obj) < 1) {
                    free(root);
                    free(json_str);
                    json_object_put(obj);
                    free(btwn);
                    err(__FILE__, __LINE__, tmp_obj, 0);
                    return NULL;
                }
                obj = tmp_obj;

                btwn = realloc(btwn, 1);
                if (btwn == NULL) {
                    free(root);
                    free(json_str);
                    json_object_put(obj);
                    free(btwn);
                    err(__FILE__, __LINE__, tmp_obj, 0);
                    return NULL;
                }
                btwn[0] = '\0';

                index += inc;
            } else {
                char *tmp = realloc(btwn, strlen(btwn) + 2);
                if (tmp == NULL) {
                    free(root);
                    free(json_str);
                    json_object_put(obj);
                    free(btwn);
                    err(__FILE__, __LINE__, tmp, 0);
                    return NULL;
                }
                sprintf(tmp, "%s%c", tmp, q[index]);
                btwn = tmp;
                index++;
            }
        }
        free(btwn);
    }
    free(root);
    free(json_str);
    return obj;
}

void push_json_to_lua_stack(lua_State *L, json_object *obj, char *property_name) {
    switch (json_object_get_type(obj)) {
        case json_type_object:
            lua_newtable(L);
            json_object_object_foreach(obj, key, val) {
                push_json_to_lua_stack(L, val, key);
            }
            break;
        case json_type_array:
            lua_newtable(L);
            for (int k = 0, n = json_object_array_length(obj); k < n; k++) {
                push_json_to_lua_stack(L, json_object_array_get_idx(obj, k), NULL);
                lua_rawseti(L, -2, k + 1);
            }
            break;
        case json_type_boolean:
            lua_pushboolean(L, json_object_get_boolean(obj));
            break;
        case json_type_double:
            lua_pushnumber(L, json_object_get_double(obj));
            break;
        case json_type_int:
            lua_pushinteger(L, json_object_get_int(obj));
            break;
        case json_type_string:
            char *str = strdup(json_object_to_json_string_ext(obj, JSON_C_TO_STRING_NOSLASHESCAPE));
            remove_quotes_btwn(&str);
            lua_pushstring(L, str);
            free(str);
            break;
        default:
            lua_pushnil(L);
    }
    if (property_name != NULL) lua_setfield(L, -2, property_name);
}

lua_State *lua_param_stack(node *parent, int param_count, pair *params) {
    lua_State *L = luaL_newstate();
    if (L == NULL) {
        free_node_tree(parent);
        err(__FILE__, __LINE__, NULL, 0);
        return NULL;
    }
    luaL_openlibs(L);
    for (int i = 0; i < param_count; i++) {
        if (params[i].key == NULL) continue;
        char *val = params[i].value;
        if (val != NULL) {
            struct json_object *obj = json_tokener_parse(val);
            if (obj != NULL) {
                push_json_to_lua_stack(L, obj, NULL);
                json_object_put(obj);
            } else {
                char *end;
                float to_num = strtod(val, &end);

                if (val != end && *end == '\0') {
                    lua_pushnumber(L, to_num);
                } else if (strcmp(val, "false") == 0) {
                    lua_pushboolean(L, 0);
                } else lua_pushstring(L, val);
            }
        } else lua_pushnil(L);
        lua_setglobal(L, params[i].key);
    }
    return L;
}

void parse_node_tree(node *doc, const char *html_buf, char **extends_from) {
    *extends_from = NULL;

    doc->content = NULL;
    doc->children = malloc(sizeof(node));
    if (doc->children == NULL) {
        err(__FILE__, __LINE__, NULL, 0);
        return;
    }
    doc->num_children = 0;

    stack_node *stack = malloc(sizeof(stack_node)); // NOTE: Stack implemented as linked list for quick insertion & deletion
    if (stack == NULL) {
        err(__FILE__, __LINE__, doc->children, 0);
        return;
    }
    stack->node = doc;
    stack->next = NULL;

    int i = 0;
    int n = strlen(html_buf);

    token *tokenlist = (token *) malloc(sizeof(token));
    if (tokenlist == NULL) {
        free_node_tree(doc);
        err(__FILE__, __LINE__, stack, 0);
        return;
    }
    int num_tokens = 0;

    TType state = TEXT;
    char *built = malloc(1);
    if (built == NULL) {
        free_node_tree(doc);
        free(stack);
        free(tokenlist);
        err(__FILE__, __LINE__, built, 0);
        return;
    }
    built[0] = '\0';

    // Lexer
    while (i < n) {
        if (strncmp(&html_buf[i], "{{ ", 3) == 0) {
            create_token(&tokenlist, state, built, &num_tokens);
            state = VAR;
            i += 3;
        } else if (strncmp(&html_buf[i], " }}", 3) == 0 || strncmp(&html_buf[i], " %}", 3) == 0) {
            create_token(&tokenlist, state, built, &num_tokens);
            state = TEXT;
            i += 3;
        } else if (strncmp(&html_buf[i], "{% if ", 6) == 0) {
            create_token(&tokenlist, state, built, &num_tokens);
            state = IF;
            i += 6;
        } else if (strncmp(&html_buf[i], "{% else %}", 10) == 0) {
            create_token(&tokenlist, state, built, &num_tokens);
            create_token(&tokenlist, ELSE, NULL, &num_tokens);
            state = TEXT;
            i += 10;
        } else if (strncmp(&html_buf[i], "{% endif %}", 11) == 0) {
            create_token(&tokenlist, state, built, &num_tokens);
            create_token(&tokenlist, ENDIF, NULL, &num_tokens);
            state = TEXT;
            i += 11;
        } else if (strncmp(&html_buf[i], "{% for ", 7) == 0) {
            create_token(&tokenlist, state, built, &num_tokens);
            state = FOR;
            i += 7;
        } else if (strncmp(&html_buf[i], "{% endfor %}", 12) == 0) {
            create_token(&tokenlist, state, built, &num_tokens);
            create_token(&tokenlist, ENDFOR, NULL, &num_tokens);
            state = TEXT;
            i += 12;
        } else if (strncmp(&html_buf[i], "{% extends ", 11) == 0) {
            create_token(&tokenlist, state, built, &num_tokens);
            state = EXTENDS;
            i += 11;
        } else if (strncmp(&html_buf[i], "{% block ", 9) == 0) {
            create_token(&tokenlist, state, built, &num_tokens);
            state = BLOCK;
            i += 9;
        } else if (strncmp(&html_buf[i], "{% endblock %}", 14) == 0) {
            create_token(&tokenlist, state, built, &num_tokens);
            create_token(&tokenlist, ENDBLOCK, NULL, &num_tokens);
            state = TEXT;
            i += 14;
        } else {
            if (i >= n - 1) {
                create_token(&tokenlist, state, built, &num_tokens);
                break;
            }

            char *temp = realloc(built, strlen(built) + 2);
            if (temp == NULL) {
                free(temp);
                err(__FILE__, __LINE__, temp, 0);
            } else {
                sprintf(temp, "%s%c", temp, html_buf[i]);
                built = temp;
            }
            i++;
        }
    }
    free(built);

    node *current_parent = stack->node;
    node **current_children = current_parent->children;
    size_t *num_child_ptr = &(current_parent->num_children);

    // Parser
    for (int j = 0; j < num_tokens; j++) {
        token *parsing = &tokenlist[j];
        switch (parsing->type) {
            case EXTENDS:
                if (parsing->content[0] == '\"' && parsing->content[strlen(parsing->content) - 1] == '\"') {
                    *extends_from = strndup(&parsing->content[1], strlen(parsing->content) - 2);
                    if (extends_from == NULL) err(__FILE__, __LINE__, NULL, 0);
                } else *extends_from = parsing->content;
                break;
            case ENDIF:
            case ENDFOR:
            case ENDBLOCK:
                if (parsing->type == ENDBLOCK && get_block(current_parent->content) == NULL) {
                    node **tmp_blocks = realloc(blocks, sizeof(node) * (num_blocks + 1));
                    if (tmp_blocks == NULL) {
                        free_node_tree(doc);
                        free_stack(stack);
                        free_token_list(tokenlist, num_tokens);
                        err(__FILE__, __LINE__, tmp_blocks, 0);
                        return;
                    } else {
                        tmp_blocks[num_blocks++] = current_parent;
                        blocks = tmp_blocks;
                    }
                }
                stack_node *tmp = stack->next;
                free(stack);
                stack = tmp;

                current_parent = stack->node;
                current_children = current_parent->children;
                num_child_ptr = &(current_parent->num_children);
                break;
            case ELSE:
                current_parent->sec_children = malloc(sizeof(node));
                if (current_parent->sec_children == NULL) {
                    free_node_tree(doc);
                    free_stack(stack);
                    free_token_list(tokenlist, num_tokens);
                    err(__FILE__, __LINE__, NULL, 0);
                    return;
                }
                current_children = current_parent->sec_children;
                num_child_ptr = &(current_parent->num_sec_children);
                break;
            default:
                int using_sec = current_children != current_parent->children;
                node **temp_list = realloc(current_children, sizeof(node) * (*num_child_ptr + 1)); // error here
                if (temp_list == NULL) {
                    free_node_tree(doc);
                    free_stack(stack);
                    free_token_list(tokenlist, num_tokens);
                    err(__FILE__, __LINE__, temp_list, 0);
                    return;
                }
                temp_list[*num_child_ptr] = malloc(sizeof(node));
                node *new_child = temp_list[*num_child_ptr];
                if (temp_list[*num_child_ptr] == NULL) {
                    free_node_tree(doc);
                    free_stack(stack);
                    free_token_list(tokenlist, num_tokens);
                    err(__FILE__, __LINE__, temp_list, 0);
                    return;
                }
                new_child->type = parsing->type;
                new_child->content = strdup(parsing->content);

                new_child->num_children = 0;
                new_child->num_sec_children = 0;

                current_children = temp_list;

                if (using_sec == 0) {
                    stack->node->children = current_children;
                } else stack->node->sec_children = current_children;
                (*num_child_ptr)++;

                if (parsing->type == IF || parsing->type == FOR || parsing->type == BLOCK) {
                    stack_node *tmp = malloc(sizeof(stack_node));
                    if (tmp == NULL) {
                        free_node_tree(doc);
                        free_stack(stack);
                        free_token_list(tokenlist, num_tokens);
                        err(__FILE__, __LINE__, NULL, 0);
                        return;
                    }
                    tmp->node = new_child;
                    tmp->next = stack;
                    stack = tmp;

                    current_parent = stack->node;
                    current_parent->children = malloc(sizeof(node));
                    if (current_parent->children == NULL) {
                        free_node_tree(doc);
                        free_stack(stack);
                        free_token_list(tokenlist, num_tokens);
                        err(__FILE__, __LINE__, NULL, 0);
                        return;
                    }

                    current_children = current_parent->children;
                    num_child_ptr = &(current_parent->num_children);
                }
        }
    }
    free_token_list(tokenlist, num_tokens);
    free_stack(stack);
}

void render(char **output, node *parent, int param_count, pair *params, int using_prim) {
    node **children = using_prim >= 1 ? parent->children : parent->sec_children;
    size_t *num = using_prim >= 1 ? &parent->num_children : &parent->num_sec_children;

    lua_State *L = NULL;

    for (int i = 0, n = *num; i < n; i++) {
        node *child = children[i];
        switch (child->type) {
            case EXTENDS:
                break;
            case BLOCK:
                node *block = get_block(child->content);
                if (block != NULL) render(output, block, param_count, params, 1);
                break;
            case FOR:
                int sep = strstr(child->content, " in ") - child->content;
                char *it = strndup(child->content, sep);
                char *coll = &child->content[sep + 4];
                if (it == NULL || coll == NULL) continue;

                remove_spaces_btwn(it);
                remove_spaces_btwn(coll);

                void *json_obj;
                if ((json_obj = get_json_obj(coll, param_count, params)) != NULL) {
                    switch (json_object_get_type(json_obj)) {
                        case json_type_object:
                            json_object_object_foreach(json_obj, key, val) {
                                pair new_p[(param_count + 1) * sizeof(*params)];
                                memcpy(new_p, params, param_count * sizeof(*params));

                                new_p[param_count].key = strdup(it);
                                new_p[param_count].value = strdup(key);
                                if (new_p[param_count].key == NULL || new_p[param_count].value == NULL) {
                                    free_node_tree(parent);
                                    free(it);
                                    if (new_p[param_count].key) free(new_p[param_count].key);
                                    if (new_p[param_count].value) free(new_p[param_count].value);
                                    err(__FILE__, __LINE__, NULL, 0);
                                    return;
                                }

                                render(output, child, param_count + 1, new_p, 1);

                                free(new_p[param_count].key);
                                free(new_p[param_count].value);
                            }
                            break;
                        case json_type_array:
                            for (int k = 0, n = json_object_array_length(json_obj); k < n; k++) {
                                pair new_p[(param_count + 1) * sizeof(*params)];
                                memcpy(new_p, params, param_count * sizeof(*params));

                                new_p[param_count].key = strdup(it);
                                new_p[param_count].value = strdup(json_object_to_json_string_ext(json_object_array_get_idx(json_obj, k), JSON_C_TO_STRING_NOSLASHESCAPE));
                                if (new_p[param_count].key == NULL || new_p[param_count].value == NULL) {
                                    free_node_tree(parent);
                                    free(it);
                                    if (new_p[param_count].key) free(new_p[param_count].key);
                                    if (new_p[param_count].value) free(new_p[param_count].value);
                                    err(__FILE__, __LINE__, NULL, 0);
                                    return;
                                }

                                render(output, child, param_count + 1, new_p, 1);

                                free(new_p[param_count].key);
                                free(new_p[param_count].value);
                            }
                            break;
                        default:
                            break;
                    }
                    json_object_put(json_obj);
                } else if (strncmp(coll, "range(", 6) == 0) {
                    int num_sep = strchr(coll, ',') - coll;

                    char *start_str = strndup(&coll[6], num_sep - 6);
                    if (start_str == NULL) {
                        free_node_tree(parent);
                        free(it);
                        err(__FILE__, __LINE__, NULL, 0);
                        return;
                    }
                    remove_spaces_btwn(start_str);
                    int start = atoi(start_str);

                    char *end_str = strndup(&coll[num_sep + 1], strlen(coll) - num_sep - 1);
                    if (end_str == NULL) {
                        free_node_tree(parent);
                        free(it);
                        err(__FILE__, __LINE__, NULL, 0);
                        return;
                    }
                    remove_spaces_btwn(end_str);
                    int end = atoi(end_str);

                    free(start_str);
                    free(end_str);
                    for (int i = start; i < end; i++) {
                        pair new_p[(param_count + 1) * sizeof(*params)];
                        memcpy(new_p, params, param_count * sizeof(*params));
                        new_p[param_count].key = strdup(it);
                        new_p[param_count].value = malloc(num_digits(i) + 1);
                        if (new_p[param_count].key == NULL || new_p[param_count].value == NULL) {
                            free_node_tree(parent);
                            free(it);
                            if (new_p[param_count].key) free(new_p[param_count].key);
                            if (new_p[param_count].value) free(new_p[param_count].value);
                            err(__FILE__, __LINE__, NULL, 0);
                            return;
                        }
                        sprintf(new_p[param_count].value, "%i", i);
                        render(output, child, param_count + 1, new_p, 1);

                        free(new_p[param_count].key);
                        free(new_p[param_count].value);
                    }
                }
                free(it);
                break;
            case IF:
                char *condition = child->content;

                if (!L) {
                    L = lua_param_stack(parent, param_count, params);
                    if (L == NULL) {
                        free_node_tree(parent);
                        err(__FILE__, __LINE__, NULL, 0);
                        return;
                    }
                }

                char *return_what = malloc(7 + strlen(condition) + 1);
                if (return_what == NULL) {
                    free_node_tree(parent);
                    err(__FILE__, __LINE__, NULL, 0);
                    lua_close(L);
                    return;
                }
                sprintf(return_what, "return %s", condition);
                luaL_dostring(L, return_what);
                free(return_what);

                render(output, child, param_count, params, lua_toboolean(L, -1));
                lua_pop(L, 1);
                break;
            case VAR:
                char *val;
                if ((val = search_keys_val_in(child->content, param_count, params)) == NULL) {
                    if (!L) {
                        L = lua_param_stack(child, param_count, params);
                        if (L == NULL) {
                            free_node_tree(parent);
                            err(__FILE__, __LINE__, NULL, 0);
                            return;
                        }
                    }
                    char *return_var = malloc(7 + strlen(child->content) + 1);
                    if (return_var == NULL) {
                        free_node_tree(parent);
                        lua_close(L);
                        err(__FILE__, __LINE__, NULL, 0);
                        return;
                    }
                    sprintf(return_var, "return %s", child->content);

                    int lua_succeeded = luaL_dostring(L, return_var) == LUA_OK;
                    free(return_var);

                    const char *to_str = lua_tostring(L, -1);
                    char *ret = lua_succeeded == 1 && to_str != NULL ? strdup(to_str) : NULL;
                    if (ret != NULL) {
                        decode(ret);
                        char *sanitized = sanitize(ret);
                        if (sanitized == NULL) {
                            free_node_tree(parent);
                            lua_close(L);
                            free(ret);
                            free(sanitized);
                            err(__FILE__, __LINE__, NULL, 0);
                            return;
                        }
                        append(output, sanitized);
                        free(sanitized);
                    }
                    free(ret);
                    lua_pop(L, 1);
                } else {
                    decode(val);
                    remove_quotes_btwn(&val);
                    char *sanitized = sanitize(val);
                    if (sanitized == NULL) {
                        free_node_tree(parent);
                        free(val);
                        free(sanitized);
                        err(__FILE__, __LINE__, NULL, 0);
                        return;
                    }
                    append(output, sanitized);
                    free(sanitized);
                    free(val);
                }
                break;
            default:
                char *text = child->content;
                if (text == NULL) continue;
                append(output, text);
        }
    }
    if (L) lua_close(L);
}

char *rendered_template(const char *html_buf, int param_count, pair *params) {
    node *doc = malloc(sizeof(node)), *ext;
    if (doc == NULL) {
        err(__FILE__, __LINE__, NULL, 0);
        return strdup(html_buf);
    }

    blocks = malloc(sizeof(node));

    char *new_buf = malloc(1);
    if (blocks == NULL || new_buf == NULL) {
        free_node_tree(doc);
        err(__FILE__, __LINE__, blocks, 0);
        return strdup(html_buf);
    }
    new_buf[0] = '\0';

    char *extends_from;
    parse_node_tree(doc, html_buf, &extends_from); // NOTE: Mainly to add the blocks into the blocks array first (if inheriting)
    if (extends_from != NULL) { // NOTE: Assuming no grandparent
        ext = malloc(sizeof(node));
        if (ext == NULL) {
            free_node_tree(doc);
            free(blocks);
            err(__FILE__, __LINE__, new_buf, 0);
            return strdup(html_buf);
        }

        char *path = malloc(strlen(extends_from) + 12 + 1);
        if (path == NULL) {
            free_node_tree(doc);
            free(blocks);
            free(new_buf);
            err(__FILE__, __LINE__, ext, 0);
            return strdup(html_buf);
        }
        sprintf(path, "../frontend/%s", extends_from);

        FILE *f = fopen(path, "r");
        free(path);
        if (f == NULL) {
            free_node_tree(doc);
            free(blocks);
            free(new_buf);
            err(__FILE__, __LINE__, ext, 0);
            return strdup(html_buf);
        }
        int size = f_size(f);

        char ext_buf[size + 1];
        fread(ext_buf, sizeof(char), size, f);
        ext_buf[size] = '\0';

        parse_node_tree(ext, ext_buf, &extends_from);
        fclose(f);
        render(&new_buf, ext, param_count, params, 1);
        if (ext) free_node_tree(ext);
    } else render(&new_buf, doc, param_count, params, 1);

    if (extends_from) free(extends_from);
    if (doc) free_node_tree(doc);
    if (blocks) free(blocks);
    num_blocks = 0;
    return new_buf;
}
