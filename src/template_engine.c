#include <errno.h>

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

node **blocks;
int num_blocks = 0;

void free_node_tree(node *root) {
    if (!root) return;
    free(root->content);
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
    while (stack) {
        stack_node *tmp = stack->next;
        free(stack);
        stack = tmp;
    }
}

int decode(char *encoded) {
    if (!encoded) return 0;
    char backup[strlen(encoded) + 1];
    strlcpy(backup, encoded, sizeof(backup));
    for (int i = 0; i < strlen(encoded); i++) { // Ok to call strlen(encoded) multiple times bc dynamic resizing
        if (encoded[i] == '+')
            encoded[i] = ' ';
        else if (encoded[i] == '%') {
            char hex[3], *end;
            strlcpy(hex, &encoded[i + 1], 3);
            int decoded = strtol(hex, &end, 16);
            if (*end != '\0' || end == hex || strlen(hex) < 2) {
                strlcpy(encoded, backup, sizeof(backup));
                return 0;
            }
            encoded[i] = decoded;
            memmove(&encoded[i + 1], &encoded[i + 3], strlen(encoded) - 2);
        }
    }
    return 1;
}

long int f_size(FILE * file) {
    long int orig_pos = ftell(file);
    fseek(file, 0L, SEEK_END);
    long int s = ftell(file);
    fseek(file, 0L, orig_pos);
    return s;
}

int num_digits(int num) {
    int digits = 0;
    while (num > 0) {
        digits++;
        num /= 10;
    }
    return digits > 1 ? digits : 1;
}

void err(const char *file, const int line, void *heap_obj, const int exit_prog) {
    free(heap_obj);
    printf("%s:%i: %s\n", file, line, strerror(errno)); // perror w/ snprintf msg adds minor but unnecessary complication of error handling snprintf
    if (exit_prog > 0) exit(EXIT_FAILURE);
}

char *sanitize(const char *str) {
    char *clean = malloc(1);
    if (!clean) {
        err(__FILE__, __LINE__, NULL, 0);
        return NULL;
    }
    clean[0] = '\0';
    for (int i = 0, n = strlen(str); i < n; i++) {
        switch (str[i]) {
            case '\0':
                continue;
            default:
                size_t added_bytes = str[i] >= 0 ? 3 + num_digits(str[i]) : 1;
                clean = realloc(clean, strlen(clean) + added_bytes + 1);
                if (!clean || (str[i] >= 0 ? snprintf(clean + strlen(clean), added_bytes + 1, "&#%i", str[i]) < 0 : snprintf(clean + strlen(clean), 2, "%c", str[i]) < 0)) {
                    err(__FILE__, __LINE__, clean, 0);
                    return NULL;
                }
        }
    }
    return clean;
}

// NOTE: Uses linear search --> O(n), must be freed
char *search_keys_val_in(const char *key, int param_count, pair *params) {
    for (int i = 0; i < param_count; i++) {
        if (params[i].key && strcmp(params[i].key, key) == 0) {
            char *val = NULL;
            if (params[i].value && !(val = strdup(params[i].value))) {
                err(__FILE__, __LINE__, NULL, 0);
                break;
            }
            return val;
        }
    }
    return NULL;
}

int create_token(token **list, TType type, char *built, int *nth) {
    token *temp = realloc(*list, (*nth + 1) * sizeof(token));
    if (!temp) {
        err(__FILE__, __LINE__, NULL, 0);
        return -1;
    }
    temp[*nth].type = type;
    temp[*nth].content = built ? strdup(built) : NULL;
    if (built) {
        if (!temp[*nth].content) {
            err(__FILE__, __LINE__, temp, 0);
            return -1;
        }
        built[0] = '\0';
    }
    *list = temp;

    (*nth)++;
    return 1;
}

void free_token_list(token *list, const int size) {
    for (int i = 0; i < size; i++) {
        free(list[i].content);
    }
    free(list);
}

node *get_block(const char *var) {
    for (int i = 0; i < num_blocks; i++) {
        if (strcmp(blocks[i]->content, var) == 0) return blocks[i];
    }
    return NULL;
}

// NOTE: Intended for stack use only. Pass in -1 or other negative values for new_total_size to let func handle max size
int append(char *str, const char *add, int new_total_size) {
    if (!str || !add) return 0;
    if (new_total_size < 0) new_total_size = sizeof(str);
    const size_t orig_size = strlen(str);
    const int is_char = strlen(add) == 1;
    return is_char ? snprintf(str + orig_size, new_total_size - orig_size, "%c", *add) >= 0 : snprintf(str + orig_size, new_total_size - orig_size, "%s", add) >= 0;
}

int heap_append(char **str, const char *add, int new_total_size) {
    if (!str || !*str || !add) return 0;
    if (new_total_size < 0) new_total_size = strlen(*str) + strlen(add) + 1;
    char *temp = realloc(*str, new_total_size);
    if (!temp || !append(temp, add, new_total_size)) {
        err(__FILE__, __LINE__, NULL, 0);
        return -1;
    }
    *str = temp;
    return 1;
}

int key_exists_in_arr_pairs(const char *key, const int param_count, const pair *params) {
    for (int i = 0; i < param_count; i++) {
        if (params[i].key && key && strcmp(params[i].key, key) == 0) return 1;
    }
    return 0;
}

int safely_append_into_arr_pair(const char *key, const char *val, int *len_ptr, pair *params) {
    if (key_exists_in_arr_pairs(key, *len_ptr, params)) return 0;
    if (!(params[*len_ptr].key = strdup(key)) || !(val && (params[*len_ptr].value = strdup(val)))) return -1;
    if (!val) params[*len_ptr].value = NULL;
    (*len_ptr)++;
    return 1;
}

void remove_spaces_btwn(char *s) {
    if (!s) return;
    while (s[strlen(s) - 1] == ' ') s[strlen(s) - 1] = '\0';
    while (s[0] == ' ') memmove(&s[0], &s[1], strlen(s));
}

void remove_outer_q_marks(char *s) {
    if (!s) return;
    if (s[strlen(s) - 1] == '"') s[strlen(s) - 1] = '\0';
    if (s[0] == '"') memmove(&s[0], &s[1], strlen(s));
}

// NOTE: Only needed to get obj collection for FOR nodes
json_object *get_json_obj(const char *q, const int param_count, pair *params) {
    if (!q) return NULL;
    int n = strlen(q);
    int index = 0;

    int sep = 0; // 0 = no sep, 1 = dot, 2 = bracket
    for (int i = 0; i < n; i++) {
        if (q[i] == '.' || q[i] == '[') {
            sep = q[i] == '.' ? 1 : 2;
            index = (i + sep);
            break;
        }
    }
    char root[(sep > 0 ? index : n + 1)];
    strlcpy(root, q, sizeof(root));

    char *json_str = search_keys_val_in(root, param_count, params);
    if (!json_str) return NULL;

    json_object *obj = json_tokener_parse(json_str);
    if (obj && index > 0) {
        char btwn[strlen(q) + 1];
        btwn[0] = '\0';

        while (index < n + 1) {
            int inc = strncmp(&q[index], "[\"", 2) == 0 || strncmp(&q[index], "\"]", 2) == 0 ? 2 : strncmp(&q[index], ".", 1) == 0 || strncmp(&q[index], "[", 1) == 0 || strncmp(&q[index], "]", 1) == 0 || index >= n ? 1 : 0;
            if (inc > 0) {
                char *end;
                float num = strtod(btwn, &end);

                struct json_object *tmp_obj = NULL;
                if (btwn != end && *end == '\0') {
                    tmp_obj = json_object_array_get_idx(obj, num);
                } else if (json_object_object_get_ex(obj, btwn, &tmp_obj) < 1) {
                    json_object_put(obj);
                    err(__FILE__, __LINE__, json_str, 0);
                    return NULL;
                }
                obj = tmp_obj;
                memset(btwn, '\0', sizeof(btwn));
                index += inc;
            } else {
                char ch = q[index];
                if (append(btwn, &ch, strlen(btwn) + 2) < 1) {
                    json_object_put(obj);
                    err(__FILE__, __LINE__, json_str, 0);
                    return NULL;
                }
                index++;
            }
        }
    }
    free(json_str);
    return obj;
}

void push_json_to_lua_stack(lua_State *L, json_object *obj, const char *property_name) {
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
            const char *str = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_NOSLASHESCAPE);
            if (str) {
                char temp[strlen(str) + 1];
                strlcpy(temp, str, sizeof(temp));
                remove_outer_q_marks(temp);
                lua_pushstring(L, temp);
            } else lua_pushnil(L);
            break;
        default:
            lua_pushnil(L);
    }
    if (property_name) lua_setfield(L, -2, property_name);
}

lua_State *lua_param_stack(node *parent, const int param_count, const pair *params) {
    lua_State *L = luaL_newstate();
    if (!L) {
        free_node_tree(parent);
        err(__FILE__, __LINE__, NULL, 0);
        return NULL;
    }
    luaL_openlibs(L);
    for (int i = 0; i < param_count; i++) {
        char *key = NULL;
        if (!(key = params[i].key)) continue;
        const char *val = params[i].value;
        if (val) {
            struct json_object *obj = json_tokener_parse(val);
            if (obj) {
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
        lua_setglobal(L, key);
    }
    return L;
}

int parse_node_tree(node *doc, const char *html_buf, char **extends_from) {
    *extends_from = NULL;

    doc->content = NULL;
    doc->children = malloc(sizeof(node));
    doc->num_children = 0;

    stack_node *stack = malloc(sizeof(stack_node)); // NOTE: Stack implemented as linked list for quick insertion & deletion
    token *tokenlist = (token *) malloc(sizeof(token));
    if (!doc->children || !stack || !tokenlist) {
        free_node_tree(doc);
        err(__FILE__, __LINE__, stack, 0);
        return -1;
    }
    stack->node = doc;
    stack->next = NULL;

    int i = 0, n = strlen(html_buf), num_tokens = 0;

    TType state = TEXT;
    char *built = malloc(1);
    if (!built) {
        free_node_tree(doc);
        free(stack);
        err(__FILE__, __LINE__, tokenlist, 0);
        return -1;
    }
    built[0] = '\0';

    // Lexer
    while (i < n) {
        if (strncmp(&html_buf[i], "{{ ", 3) == 0) {
            if (create_token(&tokenlist, state, built, &num_tokens)) {
                state = VAR;
                i += 3;
            } else {
                free_node_tree(doc);
                free(stack);
                free_token_list(tokenlist, num_tokens);
                return -1;
            }
        } else if (strncmp(&html_buf[i], " }}", 3) == 0 || strncmp(&html_buf[i], " %}", 3) == 0) {
            if (create_token(&tokenlist, state, built, &num_tokens)) {
                state = TEXT;
                i += 3;
            } else {
                free_node_tree(doc);
                free(stack);
                free_token_list(tokenlist, num_tokens);
                return -1;
            }
        } else if (strncmp(&html_buf[i], "{% if ", 6) == 0) {
            if (create_token(&tokenlist, state, built, &num_tokens)) {
                state = IF;
                i += 6;
            } else {
                free_node_tree(doc);
                free(stack);
                free_token_list(tokenlist, num_tokens);
                return -1;
            }
        } else if (strncmp(&html_buf[i], "{% else %}", 10) == 0) {
            if (create_token(&tokenlist, state, built, &num_tokens) && create_token(&tokenlist, ELSE, NULL, &num_tokens)) {
                state = TEXT;
                i += 10;
            } else {
                free_node_tree(doc);
                free(stack);
                free_token_list(tokenlist, num_tokens);
                return -1;
            }
        } else if (strncmp(&html_buf[i], "{% endif %}", 11) == 0) {
            if (create_token(&tokenlist, state, built, &num_tokens) && create_token(&tokenlist, ENDIF, NULL, &num_tokens)) {
                state = TEXT;
                i += 11;
            } else {
                free_node_tree(doc);
                free(stack);
                free_token_list(tokenlist, num_tokens);
                return -1;
            }
        } else if (strncmp(&html_buf[i], "{% for ", 7) == 0) {
            if (create_token(&tokenlist, state, built, &num_tokens)) {
                state = FOR;
                i += 7;
            } else {
                free_node_tree(doc);
                free(stack);
                free_token_list(tokenlist, num_tokens);
                return -1;
            }
        } else if (strncmp(&html_buf[i], "{% endfor %}", 12) == 0) {
            if (create_token(&tokenlist, state, built, &num_tokens) && create_token(&tokenlist, ENDFOR, NULL, &num_tokens)) {
                state = TEXT;
                i += 12;
            } else {
                free_node_tree(doc);
                free(stack);
                free_token_list(tokenlist, num_tokens);
                return -1;
            }
        } else if (strncmp(&html_buf[i], "{% extends ", 11) == 0) {
            if (create_token(&tokenlist, state, built, &num_tokens)) {
                state = EXTENDS;
                i += 11;
            } else {
                free_node_tree(doc);
                free(stack);
                free_token_list(tokenlist, num_tokens);
                return -1;
            }
        } else if (strncmp(&html_buf[i], "{% block ", 9) == 0) {
            if (create_token(&tokenlist, state, built, &num_tokens)) {
                state = BLOCK;
                i += 9;
            } else {
                free_node_tree(doc);
                free(stack);
                free_token_list(tokenlist, num_tokens);
                return -1;
            }
        } else if (strncmp(&html_buf[i], "{% endblock %}", 14) == 0) {
            if (create_token(&tokenlist, state, built, &num_tokens) && create_token(&tokenlist, ENDBLOCK, NULL, &num_tokens)) {
                state = TEXT;
                i += 14;
            } else {
                free_node_tree(doc);
                free(stack);
                free_token_list(tokenlist, num_tokens);
                return -1;
            }
        } else {
            if (i >= n - 1) {
                if (create_token(&tokenlist, state, built, &num_tokens)) {
                    break;
                } else {
                    free_node_tree(doc);
                    free(stack);
                    free_token_list(tokenlist, num_tokens);
                    return -1;
                }
            }
            char c = html_buf[i];
            if (heap_append(&built, &c, strlen(built) + 2) < 1) {
                free_node_tree(doc);
                free(stack);
                free_token_list(tokenlist, num_tokens);
                return -1;
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
                if (!parsing->content || (parsing->content && !(*extends_from = strdup(parsing->content)))) {
                    free_node_tree(doc);
                    free(stack);
                    free_token_list(tokenlist, num_tokens);
                    return -1;
                }
                remove_outer_q_marks(*extends_from);
                break;
            case ENDIF:
            case ENDFOR:
            case ENDBLOCK:
                if (parsing->type == ENDBLOCK && get_block(current_parent->content) == NULL) {
                    node **tmp_blocks = realloc(blocks, sizeof(node) * (num_blocks + 1));
                    if (!tmp_blocks) {
                        free_node_tree(doc);
                        free_stack(stack);
                        free_token_list(tokenlist, num_tokens);
                        err(__FILE__, __LINE__, NULL, 0);
                        return -1;
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
                if (!current_parent->sec_children) {
                    free_node_tree(doc);
                    free_stack(stack);
                    free_token_list(tokenlist, num_tokens);
                    err(__FILE__, __LINE__, NULL, 0);
                    return -1;
                }
                current_children = current_parent->sec_children;
                num_child_ptr = &(current_parent->num_sec_children);
                break;
            default:
                int using_sec = current_children != current_parent->children;
                node **temp_list = realloc(current_children, sizeof(node) * (*num_child_ptr + 1));
                if (!temp_list) {
                    free_node_tree(doc);
                    free_stack(stack);
                    free_token_list(tokenlist, num_tokens);
                    err(__FILE__, __LINE__, NULL, 0);
                    return -1;
                }
                temp_list[*num_child_ptr] = malloc(sizeof(node));
                node *new_child = temp_list[*num_child_ptr];
                if (!temp_list[*num_child_ptr] || (parsing->content && !(new_child->content = strdup(parsing->content)))) {
                    free_node_tree(doc);
                    free_stack(stack);
                    free_token_list(tokenlist, num_tokens);
                    err(__FILE__, __LINE__, temp_list, 0);
                    return -1;
                }
                new_child->type = parsing->type;

                new_child->num_children = 0;
                new_child->num_sec_children = 0;

                current_children = temp_list;

                if (using_sec == 0) {
                    stack->node->children = current_children;
                } else stack->node->sec_children = current_children;
                (*num_child_ptr)++;

                if (parsing->type == IF || parsing->type == FOR || parsing->type == BLOCK) {
                    stack_node *tmp = malloc(sizeof(stack_node));
                    if (!tmp) {
                        free_node_tree(doc);
                        free_stack(stack);
                        free_token_list(tokenlist, num_tokens);
                        err(__FILE__, __LINE__, NULL, 0);
                        return -1;
                    }
                    tmp->node = new_child;
                    tmp->next = stack;
                    stack = tmp;

                    current_parent = stack->node;
                    current_parent->children = malloc(sizeof(node));
                    if (!current_parent->children) {
                        free_node_tree(doc);
                        free_stack(stack);
                        free_token_list(tokenlist, num_tokens);
                        err(__FILE__, __LINE__, NULL, 0);
                        return -1;
                    }

                    current_children = current_parent->children;
                    num_child_ptr = &(current_parent->num_children);
                }
        }
    }
    free_token_list(tokenlist, num_tokens);
    free_stack(stack);
    return 1;
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
                if (block) render(output, block, param_count, params, 1);
                break;
            case FOR:
                {
                    int sep = strstr(child->content, " in ") - child->content;
                    char it[sep + 1];
                    strlcpy(it, child->content, sizeof(it));
                    char *coll = &child->content[sep + 4];
                    if (!coll) continue;

                    remove_spaces_btwn(it);
                    remove_spaces_btwn(coll);

                    json_object *json_obj = NULL;
                    if ((json_obj = get_json_obj(coll, param_count, params))) {
                        int p = param_count; // Placeholder var to satisfy int *len_ptr
                        switch (json_object_get_type(json_obj)) {
                            case json_type_object:
                                json_object_object_foreach(json_obj, key, val) {
                                    pair new_p[(param_count + 1) * sizeof(*params)];
                                    memcpy(new_p, params, param_count * sizeof(*params));

                                    new_p[param_count].key = strdup(it);
                                    new_p[param_count].value = strdup(key);

                                    if (!new_p[param_count].key || !new_p[param_count].value) {
                                        free_node_tree(parent);
                                        free(new_p[param_count].key);
                                        free(new_p[param_count].value);
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

                                    if (!new_p[param_count].key || !new_p[param_count].value) {
                                        free_node_tree(parent);
                                        free(new_p[param_count].key);
                                        free(new_p[param_count].value);
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

                        char start_str[num_sep - 5];
                        strlcpy(start_str, &coll[6], sizeof(start_str));
                        remove_spaces_btwn(start_str);

                        char end_str[strlen(coll) - num_sep];
                        strlcpy(end_str, &coll[num_sep + 1], sizeof(end_str));
                        remove_spaces_btwn(end_str);

                        char *s_end, *end_end;

                        int start = strtol(start_str, &s_end, 10);
                        int end = strtol(end_str, &end_end, 10);

                        if (s_end == start_str || end_end == end_str) { // *s_end == '\0' check might not be ideal
                            free_node_tree(parent);
                            err(__FILE__, __LINE__, NULL, 0);
                            return;
                        }

                        for (int i = start; i < end; i++) {
                            size_t val_size = num_digits(i) + 1;
                            pair new_p[(param_count + 1) * sizeof(*params)];
                            memcpy(new_p, params, param_count * sizeof(*params));
                            new_p[param_count].key = strdup(it);
                            new_p[param_count].value = malloc(val_size);
                            if (!new_p[param_count].key || !new_p[param_count].value || snprintf(new_p[param_count].value, val_size, "%i", i) < 0) {
                                free_node_tree(parent);
                                free(new_p[param_count].key);
                                free(new_p[param_count].value);
                                err(__FILE__, __LINE__, NULL, 0);
                                return;
                            }
                            render(output, child, param_count + 1, new_p, 1);

                            free(new_p[param_count].key);
                            free(new_p[param_count].value);
                        }
                    }
                    break;
                }
            case IF:
                {
                    char *condition = child->content;

                    if (!L) {
                        L = lua_param_stack(parent, param_count, params);
                        if (!L) {
                            free_node_tree(parent);
                            err(__FILE__, __LINE__, NULL, 0);
                            return;
                        }
                    }

                    char return_what[7 + strlen(condition) + 1];
                    if (snprintf(return_what, sizeof(return_what), "return %s", condition) < 0 || luaL_dostring(L, return_what) != LUA_OK) {
                        free_node_tree(parent);
                        err(__FILE__, __LINE__, NULL, 0);
                        lua_close(L);
                        return;
                    }
                    render(output, child, param_count, params, lua_toboolean(L, -1));
                    lua_pop(L, 1);
                    break;
                }
            case VAR:
                {
                    char *val = NULL;
                    if (!(val = search_keys_val_in(child->content, param_count, params))) {
                        if (!L) {
                            L = lua_param_stack(child, param_count, params);
                            if (!L) {
                                free_node_tree(parent);
                                err(__FILE__, __LINE__, NULL, 0);
                                return;
                            }
                        }
                        char return_var[7 + strlen(child->content) + 1];
                        if (snprintf(return_var, sizeof(return_var), "return %s", child->content) < 0) {
                            free_node_tree(parent);
                            err(__FILE__, __LINE__, NULL, 0);
                            lua_close(L);
                            return;
                        }
                        int lua_succeeded = luaL_dostring(L, return_var) == LUA_OK;

                        const char *to_str = lua_tostring(L, -1);
                        char *sanitized = NULL;
                        if (lua_succeeded && to_str && (!(sanitized = sanitize(to_str)) || heap_append(output, sanitized, -1) < 1)) {
                            free_node_tree(parent);
                            lua_close(L);
                            err(__FILE__, __LINE__, sanitized, 0);
                            return;
                        }
                        lua_pop(L, 1);
                    } else {
                        char *sanitized = sanitize(val);
                        if (!sanitized || heap_append(output, sanitized, -1) < 1) {
                            free_node_tree(parent);
                            free(val);
                            free(sanitized);
                            err(__FILE__, __LINE__, NULL, 0);
                            return;
                        }
                        free(sanitized);
                        free(val);
                    }
                    break;
                }
            default:
                char *text = child->content;
                if (!text || heap_append(output, text, -1) < 1) continue;
        }
    }
    if (L) lua_close(L);
}

char *rendered_template(const char *html_buf, int param_count, pair *params) {
    node *doc = malloc(sizeof(node)), *ext = NULL;
    blocks = malloc(sizeof(node));
    char *new_buf = malloc(1);
    if (!doc || !blocks || !new_buf) {
        free(doc); // Not free_node_tree(doc) bc doc is just malloced
        err(__FILE__, __LINE__, blocks, 0);
        return strdup(html_buf);
    }
    new_buf[0] = '\0';
    doc->content = NULL;

    char *extends_from;
    if (parse_node_tree(doc, html_buf, &extends_from) < 1) { // NOTE: Mainly to add the blocks into the blocks array first (if inheriting)
        free_node_tree(doc);
        free(blocks);
        free(extends_from);
        return strdup(html_buf);
    }
    if (extends_from) { // NOTE: Assuming no grandparent
        ext = malloc(sizeof(node));
        char path[strlen(extends_from) + 12 + 1];
        FILE *f = NULL;

        if (!ext || snprintf(path, sizeof(path), "../frontend/%s", extends_from) < 0 || !(f = fopen(path, "r"))) {
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
        fclose(f);

        if (parse_node_tree(ext, ext_buf, &extends_from) < 1) {
            free_node_tree(doc);
            free(blocks);
            free(new_buf);
            err(__FILE__, __LINE__, ext, 0);
            return strdup(html_buf);
        }
        render(&new_buf, ext, param_count, params, 1);
        free_node_tree(ext);
    } else render(&new_buf, doc, param_count, params, 1);

    free(extends_from);
    free_node_tree(doc);
    free(blocks);
    num_blocks = 0;
    return new_buf;
}
