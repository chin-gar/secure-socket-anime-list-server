#define MAX_HTTP_SIZE 16384
#define MAX_QUERIES 50
#define CHUNK_SIZE 10
#define MAX_EVENTS 100
#define URL_CHAR_LIMIT 300
#define API_URL "kitsu.io"

#include <argon2.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/prov_ssl.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <pthread.h>
#include <regex.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "template_engine.h"
#include <time.h>
#include <unistd.h>

pthread_mutex_t lock;

SSL_CTX *ctx, *sctx;

struct epoll_event ev, events[MAX_EVENTS];
int epoll_fd;
int fd_size = 1;

// Rate limiting
struct token_bucket {
    time_t last_updated;
    int tokens;
    int max_capacity;
    int fill_rate; // tokens/sec
};

struct ip_entry {
    char *ip;
    struct token_bucket bucket;
    int active_connections;
    time_t last_connected;
};

struct ip_entries_as_func_param {
    struct ip_entry **entries;
    int *num_ips_ptr;
};

typedef struct connection { // NOTE: Made to implement token bucket and pass properties such as ip addr and port, replaced client fd as handle param and is events[i].data.ptr
    int fd;
    uint16_t port; // NOTE: 2^16 = 65536 ports, including port 0
    struct ip_entry *entry_ptr;
    SSL *ssl;
} connection;

// NOTE: 1 on success; 0 on failure
int to_json_str_from_res(char **res_ptr) {
    char *no_header = strstr(*res_ptr, "\r\n\r\n") + 4;
    char *json = strchr(no_header, '{');
    if (strstr(*res_ptr, "Transfer-Encoding: chunked\r\n") == NULL) {
        *res_ptr = strdup(json);
        return 1;
    }
    char *c_str = strndup(no_header, json - no_header);
    if (c_str == NULL) {
        err(__FILE__, __LINE__, NULL, 0);
        return 0;
    }
    remove_spaces_btwn(c_str);
    int hex = atoi(c_str);
    int c_size = strtol(c_str, NULL, 16);

    char sep[num_digits(c_size) + 5];
    sprintf(sep, "\r\n%i\r\n", hex);

    char *new = strndup(json, c_size);
    if (new == NULL) {
        err(__FILE__, __LINE__, c_str, 0);
        return 0;
    }
    int index = c_size + strlen(sep);

    while (index < strlen(json)) {
        char *tmp_new = realloc(new, strlen(new) + c_size);
        if (tmp_new == NULL) {
            free(c_str);
            err(__FILE__, __LINE__, tmp_new, 0);
            return 0;
        }
        strncpy(&tmp_new[strlen(new)], &json[index], c_size);
        new = tmp_new;
        index+=(c_size + strlen(sep));
    }
    free(c_str);
    free(*res_ptr);
    *res_ptr = new;
    return 1;
}

// NOTE: Must be freed
char *http_req(const char *path, const char *host, char *type, const char *additional) {
    if (additional == NULL) additional = "";
    char *req = malloc(strlen(type) + 1 + strlen(path) + 17 + 19 + strlen(host) + 4 + strlen(additional) + 1);
    if (req == NULL) {
        err(__FILE__, __LINE__, NULL, 0);
        return NULL;
    }
    sprintf(req, "%s %s HTTP/1.1\r\nConnection: close\r\nHost: %s\r\n\r\n%s", type, path, host, additional);
    return req;
}

void close_conn(connection *conn) {
    if (!conn) return;
    conn->entry_ptr->active_connections--;
    fd_size--;
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    close(conn->fd);
    SSL_shutdown(conn->ssl);
    SSL_free(conn->ssl);
    if (conn) free(conn);
}

void completely_send(connection * conn, const char *buf, const size_t len) {
    size_t sent = 0, total = 0;
    while (total < len) {
        int status = SSL_write_ex(conn->ssl, &buf[total], len - total, &sent);
        if (status > 0) {
            total += sent;
            continue;
        }
        int err_code = SSL_get_error(conn->ssl, status);
        if (err_code == SSL_ERROR_WANT_READ || err_code == SSL_ERROR_WANT_WRITE) return;

        close_conn(conn);
        return;
    }
}

// NOTE: Must be freed
char *recv_https_from_req(const char *path, const char *host, const char *type, const char *additional) {
    struct addrinfo hints, *res, *it;
    int api_fd = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, "443", &hints, &res) == -1) {
        err(__FILE__, __LINE__, NULL, 0);
        return NULL;
    }

    for (it = res; it != NULL; it = it->ai_next) {
        api_fd = socket(hints.ai_family, hints.ai_socktype, 0);
        if (api_fd == -1) continue;
        if (connect(api_fd, res->ai_addr, res->ai_addrlen) != -1) break;
        close(api_fd);
    }
    freeaddrinfo(res);

    if (it != NULL) {
        SSL *ssl = SSL_new(ctx);
        if (ssl == NULL) {
            err(__FILE__, __LINE__, NULL, 0);
            close(api_fd);
            return NULL;
        }

        BIO *bio = BIO_new(BIO_s_socket());
        if (bio == NULL) {
            err(__FILE__, __LINE__, NULL, 0);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            BIO_free(bio);
            close(api_fd);
            return NULL;
        }
        BIO_set_fd(bio, api_fd, BIO_CLOSE);
        SSL_set_bio(ssl, bio, bio);

        char *api_req = http_req(path, host, "GET", additional);

        char *buf = malloc(1);
        if (SSL_set_tlsext_host_name(ssl, host) < 1 || SSL_connect(ssl) < 1 || !api_req || !buf) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            err(__FILE__, __LINE__, api_req, 0);

            char err[256];
            ERR_error_string_n(ERR_get_error(), err, sizeof(err));
            printf("%s\n", err);

            free(buf);
            return NULL;
        }
        buf[0] = '\0';
        size_t written;
        SSL_write_ex(ssl, api_req, strlen(api_req), &written);

        free(api_req);

        int read_total = 0;
        while (1) {
            char *tmp = realloc(buf, strlen(buf) + CHUNK_SIZE + 1);
            if (tmp == NULL) {
                break;
            }
            size_t read;
            int status = SSL_read_ex(ssl, &tmp[read_total], CHUNK_SIZE, &read);
            tmp[read_total + read] = '\0';
            buf = tmp;
            if (status <= 0) break;
            read_total += read;
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(api_fd);
        return buf;
    }
    return NULL;
}

// NOTE: Must be freed
char *http_res(void *body, char *type, int content_len, int status, char *more_header_info) {
    if (status <= 0) status = 200;
    if (more_header_info == NULL) more_header_info = "";

    char c_len_str[16 + num_digits(content_len) + 1];
    sprintf(c_len_str, "Content-Length: %i", content_len);

    char c_type_str[14 + strlen(type) + 1];
    sprintf(c_type_str, "Content-Type: %s", type);

    int h_len = 21 + strlen(c_len_str) + strlen(c_type_str) + strlen(more_header_info) + (strlen(more_header_info) > 0 ? 2 : 2);
    //int h_len = 21 + strlen(c_len_str) + strlen(c_type_str) + strlen(more_header_info);
    int res_size = h_len + content_len + 1;
    char *res = malloc(res_size);
    if (res == NULL) {
        err(__FILE__, __LINE__, NULL, 0);
        return NULL;
    }
    // FIXME: Res only valid w/ header & body sep being 3 \r\n's (haven't observed w/ more_header_info)
    sprintf(res, "HTTP/1.1 %i\r\n%s\r\n%s\r\n%s\r\n", status, c_type_str, c_len_str, more_header_info);
    //sprintf(res, "HTTP/1.1 %i\r\n%s\r\n%s\r\n", status, c_type_str, c_len_str);
    //if (strlen(more_header_info) > 0) sprintf(res, "%s%s\r\n", res, more_header_info);
    if (400 <= status && status < 600) {
        sprintf(res, "%s\r\n", res);
        return res;
    } else if (strncmp(type, "text", 4) == 0 || strcmp(type, "application/json") == 0)
         sprintf(res, "%s\r\n%s", res, (char *) body);
    else {
        memcpy(res + h_len - 1, body, content_len);
    }
    return res;
}

// TODO: Determine if func needs to return int status code & if args[0] should become pair * & for no params to have to call NULL
// NOTE: args[0] = pair[]
void send_file_to(connection *conn, char *name, char *type, int num_args, ...) {
    va_list args;
    va_start(args, num_args);
    pair *params = num_args > 0 ? va_arg(args, pair *) : NULL;
    if (type == NULL || strcmp(type, "") == 0) type = "text/html";

    char p_name[12 + strlen(name) + 1];
    sprintf(p_name, "../frontend/%s", name);

    int len = 0, status = 200;
    size_t total = 0;
    size_t sent = 0;

    FILE *f = fopen(p_name, "rb");
    if (f != NULL) len = f_size(f);
    else status = 404;

    char *buf = malloc(len + 1);
    if (buf == NULL) {
        va_end(args);
        if (f != NULL) fclose(f);
        err(__FILE__, __LINE__, NULL, 0);
        return;
    }

    if (f != NULL) {
        int s = fread(buf, len, 1, f);
        if (s < 0) status = 404;
        buf[len] = '\0';
        if (strcmp(type,"text/html") == 0) {
            char *tmp = rendered_template(buf, num_args, params);
            if (tmp != NULL) {
                free(buf);
                buf = tmp;
                len = strlen(buf);
            }
        }
    }
    if (f != NULL) fclose(f);

    char *sid = search_keys_val_in("set_session", num_args, params);
    char set_cookie[55 + (params && sid ? strlen(sid) : 0)];

    if (sid) {
        sprintf(set_cookie, "Set-Cookie: session=%s; HttpOnly; SameSite=Lax; Secure", sid);
    } else set_cookie[0] = '\0';
    char *res = http_res(buf, type, len + 1, status, set_cookie);
    if (res == NULL) {
        va_end(args);
        err(__FILE__, __LINE__, buf, 0);
        return;
    }
    int res_len = strncmp(type, "text", 4) == 0 ? strlen(res) : len + strlen(res);
    for (int i = 0; i < (sid ? 2 : 1); i++) completely_send(conn, res, res_len + 1); // NOTE: multiprint = temp workaround problem where epoll_wait hangs when HTTP req w/ set_session
    va_end(args);
    free(buf);
    free(res);
}

// NOTE: Must be freed
char *url_from_get_req(const char *req) {
    if (!req || !strchr(req, '/')) return NULL;
    const char *start = &req[strchr(req, ' ') - req + 1];
    if (!start) return NULL;
    return strndup(start, strlen(start) - strlen(strchr(start, ' ')));
}

// TODO: Try iterating thru each char or rethink how this should work
void insert_into_pair(const char *query_str, pair *p) {
    int eq_sep = strchr(query_str, '=') - query_str;
    p->key = strndup(query_str, eq_sep);
    decode(p->key);

    const char *and_up = strchr(query_str, '&');
    int val_size = (and_up ? and_up - query_str - eq_sep - 1 : strlen(query_str) - eq_sep);
    p->value = strndup(&query_str[eq_sep + 1], val_size);
    decode(p->value);
}

// TODO: Search to see if key already exists, fail if true
int url_query_into_arr_pairs(const char *query_str, int *len_ptr, pair *p) {
    if (strcmp(query_str, "") == 0 || strcmp(query_str, "/") == 0 || !strchr(query_str, '=')) return 0;
    const char *question_marker = strchr(query_str, '?');
    char *queries = strdup(question_marker ? question_marker + 1 : query_str);
    if (!queries) return -1;

    while (*len_ptr < MAX_QUERIES) {
        insert_into_pair(queries, &p[*len_ptr]);
        (*len_ptr)++;
        const char *next_and = strchr(queries, '&');
        if (next_and) {
            memmove(queries, next_and + 1, strlen(queries) - (next_and - queries));
            queries[strlen(queries)] = '\0';
        } else break;
    }
    free(queries);
    return 1;
}

int min(int a, int b) {
    return a < b ? a : b;
}

int consume_bucket(connection *conn, int num_tokens_to_consume) {
    struct token_bucket *bucket = &conn->entry_ptr->bucket;
    time_t now;
    time(&now);
    bucket->tokens += (difftime(now, bucket->last_updated) * bucket->fill_rate);
    bucket->tokens = min(bucket->tokens, bucket->max_capacity);
    bucket->last_updated = now;
    if (bucket->tokens < num_tokens_to_consume) {
        send_file_to(conn, "429.html", NULL, 0);
        return 0;
    }
    bucket->tokens -= num_tokens_to_consume;
    return 1;
}

void *rm_expired_sessions(void *arg) { // NOTE: arg = ip_entry[]
    struct ip_entries_as_func_param *params = (struct ip_entries_as_func_param *) arg;
    struct ip_entry *ip_entries = (struct ip_entry *) params->entries;

    // TODO: Is opening data.db once and leaving it open gonna cause db access conflicts?
    sqlite3 *db;
    if (sqlite3_open("data.db", &db) != SQLITE_OK) {
        err(__FILE__, __LINE__, NULL, 0);
        printf("Error opening data.db for rm_exp_thr: %s\n", sqlite3_errmsg(db));
        return NULL;
    }
    while (1) {
        pthread_mutex_lock(&lock);
        if (sqlite3_exec(db, "DELETE FROM sessions WHERE expires_at <= datetime('now');", NULL, NULL, NULL) != SQLITE_OK) {
            err(__FILE__, __LINE__, NULL, 0);
            printf("Error deleting sessions in rm_expired_sessions: %s\n", sqlite3_errmsg(db));
        }
        for (int i = 0, n = *(params->num_ips_ptr); i < n; i++) {
            time_t now = time(NULL);
            if (ip_entries[i].active_connections <= 0 && difftime(mktime(gmtime(&now)), ip_entries[i].last_connected) / 60 >= 30) {
                free(ip_entries[i].ip);
                (*(params->num_ips_ptr))--;
                memmove(&ip_entries[i], &ip_entries[i + 1], sizeof(*ip_entries) * (n - i - 1));
                i--;
            }
        }
        pthread_mutex_unlock(&lock);
        sleep(600); // NOTE: Every 10 mins
    }
    sqlite3_close(db);
    return NULL;
}

void *handle(void *arg) { // NOTE: arg = connection * of client data ptr
    connection *conn = (connection *) arg;
    const int cli = conn->fd;
    SSL *ssl = conn->ssl;

    char r[MAX_HTTP_SIZE + 1];
    r[0] = '\0';

    size_t bytes = 0, received = 0;

    int status = -1;
    while (1) {
        int status = SSL_read_ex(ssl, &r[bytes], CHUNK_SIZE, &received);
        if (status > 0) {
            bytes += received;
            r[bytes] = '\0';
            continue;
        }
        int err_code = SSL_get_error(ssl, status);
        if (err_code == SSL_ERROR_WANT_READ || err_code == SSL_ERROR_WANT_WRITE) break;

        close_conn(conn);
        return NULL;
    };
    if (bytes <= 0) {
        close_conn(conn);
        return NULL;
    }
    time_t now = time(NULL);
    conn->entry_ptr->last_connected = mktime(gmtime(&now));

    // TODO: Use MAX_QUERIES macro instead
    const int max_queries = 50;

    // TODO: Rethink abt max_params size
    pair params[2 + max_queries + 1]; // NOTE: 0, 1 for session & errmsg; max url queries; 1 for results
    int num_params = 0;

    //NOTE: Iterates thru header chars/properties JUST to look for session cookie FOR NOW
    int reading_cookie = 0;
    char session[255];
    session[0] = '\0';
    for (int i = 0, n = strlen(r); i < n; i++) {
        if (strncmp(&r[i], "session=", 8) == 0) {
            reading_cookie = 1;
            i += 7;
        } else if (reading_cookie) {
            if (strncmp(&r[i], "\r\n", 2) == 0 || r[i] == ';')
                break;
            sprintf(session, "%s%c", session, r[i]);
        }
    }
    int uid = -1;
    char *exp = NULL;

    if (strcmp(session, "") != 0) {
        decode(session);

        sqlite3 *db;
        sqlite3_stmt *stmt;
        if (sqlite3_open("data.db", &db) != SQLITE_OK || sqlite3_prepare_v2(db, "SELECT uid, expires_at FROM sessions WHERE id = ? LIMIT 1;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_text(stmt, 1, session, -1, SQLITE_STATIC) != SQLITE_OK) {
            err(__FILE__, __LINE__, NULL, 0);
            printf("Finding session err: %s\n", sqlite3_errmsg(db));
            close_conn(conn);
            return NULL;
        };
        sqlite3_step(stmt);
        uid = sqlite3_column_int(stmt, 0);
        const unsigned char *column_txt = sqlite3_column_text(stmt, 1);
        exp = column_txt ? strdup((char *) column_txt) : NULL;
        sqlite3_reset(stmt);
        if (uid > 0 || exp != NULL) {
            struct tm exp_tm = {0};
            strptime(exp, "%Y-%m-%d %H:%M:%S", &exp_tm);

            time_t exp_time_t = mktime(&exp_tm);

            time_t now = time(NULL);
            time_t gm_now = mktime(gmtime(&now));

            int diff = difftime(gm_now, exp_time_t) / 60;
            if (diff >= 0) {
                params[0].key = strdup("set_session");
                params[0].value = strdup("");
            } else {
                params[0].key = strdup("session");
                params[0].value = strdup(session);
            }
            if ((diff >= 0 && (sqlite3_prepare_v2(db, "DELETE FROM sessions WHERE id = ?;", -1, &stmt, NULL) != SQLITE_OK)) || (diff < 0 && sqlite3_prepare_v2(db, "UPDATE sessions SET expires_at = datetime('now', '+30 minutes') WHERE id = ?;", -1, &stmt, NULL) != SQLITE_OK)) {
                err(__FILE__, __LINE__, exp, 0);
                printf("Updating cli session err: %s\n", sqlite3_errmsg(db));
                sqlite3_close(db);
                sqlite3_finalize(stmt);
                close_conn(conn);
                return NULL;
            }
            sqlite3_bind_text(stmt, 1, session, -1, SQLITE_STATIC);
            sqlite3_step(stmt);
        } else {
            params[0].key = strdup("set_session");
            params[0].value = strdup("");
        }
        if (params[0].key == NULL || params[0].value == NULL) {
            err(__FILE__, __LINE__, exp, 0);
            sqlite3_close(db);
            sqlite3_finalize(stmt);
            close_conn(conn);
            return NULL;
        }
        num_params++;
        free(exp);
        sqlite3_close(db);
        sqlite3_finalize(stmt);
    }
    char *url = url_from_get_req(r);

    // TODO: Rethink if url char limit necessary and/or change anime search bar to match/drop req, considering encoded/decoded chars
    if (url == NULL || strlen(url) > 300) {
        params[num_params].key = strdup("err_reason");
        params[num_params].value = malloc(43 + num_digits(URL_CHAR_LIMIT) + 1);
        if (params[num_params].key == NULL || params[num_params].value == NULL) {
            send_file_to(conn, "404.html", NULL, num_params, params);
            num_params++;
        } else {
            sprintf(params[num_params].value, "Invalid URL or URL exceeds %i character limit", URL_CHAR_LIMIT);
            send_file_to(conn, "404.html", NULL, num_params, params);
            free(params[num_params].key);
            free(params[num_params].value);
        }
        free(url);
        close_conn(conn);
        return NULL;
    }
    if (strncmp(r, "GET ", 4) == 0) {
        url_query_into_arr_pairs(url, &num_params, params);
        //printf("%surl: %s from %i\nnum bytes: %i\nr len: %li\n", r, url, cli, bytes, strlen(r));
        // TODO: Set limit of num params to prevent function overload
        if (strcmp(url, "/") == 0) {
            if (consume_bucket(conn, 1)) send_file_to(conn, "index.html", NULL, num_params, params);
        } else if (strcmp(url, "/favicon.ico") == 0) {
            send_file_to(conn, "favicon.ico", "image/x-icon", 0);
        } else if (strcmp(url, "/styles.css") == 0) {
            send_file_to(conn, "styles.css", "text/css", 0);
        } else if (strcmp(url, "/search.js") == 0) {
            send_file_to(conn, "search.js", "text/javascript", 0);
        } else if (strcmp(url, "/signup") == 0 && consume_bucket(conn, 3)) {
            if (strcmp(session, "") == 0)
                send_file_to(conn, "signup.html", NULL, num_params, params);
            else send_file_to(conn, "401.html", NULL, num_params, params);
        } else if (strcmp(url, "/login") == 0 && consume_bucket(conn, 3)) {
            if (strcmp(session, "") == 0)
                send_file_to(conn, "login.html", NULL, num_params, params);
            else send_file_to(conn, "401.html", NULL, num_params, params);
        } else if ((strncmp(url, "/search?filter%5Btext%5D=", 25) == 0 || strncmp(url, "/search?filter[text]=", 21) == 0) && consume_bucket(conn, 5)) {
            char search_url[15 + strlen(&url[7]) + 1];
            sprintf(search_url, "/api/edge/anime%s", strcmp(&url[21], "") != 0 ? &url[7] : "");

            char *buf = recv_https_from_req(search_url, API_URL, "GET", NULL);
            if (buf) {
                to_json_str_from_res(&buf);
            } else {
                params[num_params].key = strdup("search_err");
                params[num_params++].value = strdup("Couldn't fetch results...");
                send_file_to(conn, "search.html", NULL, num_params, params);
                for (int i = 0; i < num_params; i++) {
                    free(params[i].key);
                    free(params[i].value);
                }
                return NULL;
            }
            params[num_params].key = strdup("results");
            if (params[num_params].key == NULL) {
                close_conn(conn);
                free(url);
                for (int i = 0; i < num_params; i++) {
                    free(params[i].key);
                    free(params[i].value);
                }
                err(__FILE__, __LINE__, NULL, 0);
                return NULL;
            }
            params[num_params++].value = buf; // NOTE: buf freed on free params loop

            if (strcmp(session, "") != 0 && uid > 0) {
                sqlite3 *db;
                sqlite3_stmt *stmt;
                if (sqlite3_open("data.db", &db) != SQLITE_OK || sqlite3_prepare_v2(db, "SELECT anime_id, episodes_watched FROM progress WHERE uid = ?;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK) {
                    err(__FILE__, __LINE__, url, 0);
                    params[num_params].key = strdup("search_err");
                    params[num_params++].value = strdup(sqlite3_errmsg(db));
                    send_file_to(conn, "search.html", NULL, num_params, params);
                    for (int i = 0; i < num_params; i++) {
                        free(params[i].key);
                        free(params[i].value);
                    }
                    return NULL;
                }
                struct json_object *anime_list = json_object_new_object();
                while (anime_list && sqlite3_step(stmt) == SQLITE_ROW) {
                    json_object_object_add(anime_list, (char *) sqlite3_column_text(stmt, 0), json_object_new_int(sqlite3_column_int(stmt, 1))); // 1st column guaranteed to not be NULL bc .schema progress;
                }
                if (json_object_object_length(anime_list) > 0) {
                    params[num_params].key = strdup("list");
                    params[num_params++].value = strdup(json_object_to_json_string_ext(anime_list, JSON_C_TO_STRING_NOSLASHESCAPE));
                }
                json_object_put(anime_list);
                sqlite3_close(db);
                sqlite3_finalize(stmt);
            }
            send_file_to(conn, "search.html", NULL, num_params, params);
        } else if (strncmp(url, "/list", 5) == 0 && consume_bucket(conn, 3)) {
            if (strcmp(session, "") != 0 && uid > 0) {
                int page = 1;
                if (strncmp(url, "/list?", 6) != 0 && strcmp(url, "/list") != 0) {
                    free(url);
                    send_file_to(conn, "400.html", NULL, num_params, params);
                    for (int i = 0; i < num_params; i++) {
                        free(params[i].key);
                        free(params[i].value);
                    }
                    return NULL;
                }
                char *end;
                char *p_str = search_keys_val_in("page", num_params, params);
                if (p_str) page = strtol(p_str ? p_str : "", &end, 10);
                if (p_str && (p_str == end || *end != '\0' || page < 1)) {
                    free(url);
                    free(p_str);
                    params[num_params].key = strdup("err_reason");
                    params[num_params++].value = strdup("Invalid page number.");
                    send_file_to(conn, "400.html", NULL, num_params, params);
                    for (int i = 0; i < num_params; i++) {
                        free(params[i].key);
                        free(params[i].value);
                    }
                    return NULL;
                }
                free(p_str);
                sqlite3 *db;
                sqlite3_stmt *stmt = NULL;

                if (sqlite3_open("data.db", &db) != SQLITE_OK) {
                    err(__FILE__, __LINE__, url, 0);
                    printf("Opening db for list err: %s\n", sqlite3_errmsg(db));
                    send_file_to(conn, "500.html", NULL, num_params, params);
                    for (int i = 0; i < num_params; i++) {
                        free(params[i].key);
                        free(params[i].value);
                    }
                    return NULL;
                }
                const int offset = (page - 1) * 20;
                char *title = search_keys_val_in("q", num_params, params);
                char pattern[title ? (strlen(title) + 2 + 1) : 1];
                pattern[0] = '\0';
                if (title) snprintf(pattern, sizeof(pattern), "%%%s%%", title);

                if ((title ? (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM (SELECT * FROM progress WHERE uid = ? AND title LIKE ? ORDER BY i DESC LIMIT 20 OFFSET ?);", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK || sqlite3_bind_text(stmt, 2, pattern, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_int(stmt, 3, offset) != SQLITE_OK) : (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM (SELECT * FROM progress WHERE uid = ? ORDER BY i ASC LIMIT 20 OFFSET ?);", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK || sqlite3_bind_int(stmt, 2, offset) != SQLITE_OK)) || sqlite3_step(stmt) != SQLITE_ROW) {
                    err(__FILE__, __LINE__, url, 0);
                    printf("List # prep err: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);
                    if (stmt) sqlite3_finalize(stmt);
                    send_file_to(conn, "500.html", NULL, num_params, params);
                    for (int i = 0; i < num_params; i++) {
                        free(params[i].key);
                        free(params[i].value);
                    }
                    return NULL;
                }
                int size = sqlite3_column_int(stmt, 0);
                sqlite3_reset(stmt);

                if (title ? (sqlite3_prepare_v2(db, "SELECT anime_id, episodes_watched FROM progress WHERE uid = ? AND title LIKE ? ORDER BY i DESC LIMIT 20 OFFSET ?;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK || sqlite3_bind_text(stmt, 2, pattern, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_int(stmt, 3, offset) != SQLITE_OK) : (sqlite3_prepare_v2(db, "SELECT anime_id, episodes_watched FROM progress WHERE uid = ? ORDER BY i ASC LIMIT 20 OFFSET ?;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK || sqlite3_bind_int(stmt, 2, offset) != SQLITE_OK)) {
                    err(__FILE__, __LINE__, url, 0);
                    printf("List prep err: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);
                    sqlite3_finalize(stmt);
                    send_file_to(conn, "500.html", NULL, num_params, params);
                    for (int i = 0; i < num_params; i++) {
                        free(params[i].key);
                        free(params[i].value);
                    }
                    return NULL;
                }

                json_object *arr = json_object_new_array_ext(size);
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char *anime_id = (char *) sqlite3_column_text(stmt, 0); // NOTE: NOT NULL bc db .schema
                    const int episodes_watched = sqlite3_column_int(stmt, 1);

                    json_object *item = json_object_new_object();
                    json_object *ep_obj = json_object_new_int(episodes_watched);

                    char endpt[16 + strlen(anime_id) + 1];
                    int endpt_status = snprintf(endpt, sizeof(endpt), "/api/edge/anime/%s", anime_id);
                    if (!item || !ep_obj || !(endpt_status < sizeof(endpt) && endpt >= 0)) {
                        if (item) json_object_put(item);
                        if (ep_obj) json_object_put(ep_obj);
                        continue;
                    }
                    char *buf = recv_https_from_req(endpt, API_URL, "GET", NULL);
                    json_object *data = NULL;
                    if (buf && to_json_str_from_res(&buf) && (data = json_tokener_parse(buf)) != NULL) {
                        json_object_object_add(item, "episodesWatched", ep_obj);
                        json_object_object_add(item, "data", json_object_object_get(data, "data"));
                        json_object_array_add(arr, item);
                    }
                    free(buf);
                }

                if (arr) {
                    const char *json_str = json_object_to_json_string_ext(arr, JSON_C_TO_STRING_NOSLASHESCAPE);
                    params[num_params].key = strdup("list");
                    params[num_params++].value = strdup(json_str);

                    send_file_to(conn, "list.html", NULL, num_params, params);
                    json_object_put(arr);
                } else send_file_to(conn, "500.html", NULL, num_params, params);

                sqlite3_close(db);
                sqlite3_finalize(stmt);
            } else send_file_to(conn, "401.html", NULL, num_params, params);
        } else send_file_to(conn, "404.html", NULL, num_params, params);
    } else if (strncmp(r, "POST ", 5) == 0) {
        printf("%s\n", r);
        char *post_body = strstr(r, "\r\n\r\n") + 4;
        if (post_body && strcmp(post_body, "") != 0) {
            url_query_into_arr_pairs(post_body, &num_params, params);
        }
        if (strncmp(url, "/signup", 7) == 0 && consume_bucket(conn, 5)) {
            if (strcmp(session, "") == 0) {
                sqlite3 *db = NULL;
                sqlite3_stmt *stmt = NULL; // NOTE: Prepared statement to prevent SQL injection atks

                if (sqlite3_open("data.db", &db) != SQLITE_OK) {
                    for (int i = 0; i < num_params; i++) {
                        free(params[i].key);
                        free(params[i].value);
                    }
                    err(__FILE__, __LINE__, NULL, 0);
                    return NULL;
                }
                const char *create_table = "CREATE TABLE IF NOT EXISTS users (" \
                                            "    id INTEGER PRIMARY KEY AUTOINCREMENT," \
                                            "    username TEXT UNIQUE NOT NULL," \
                                            "    pwd_hash VARCHAR(255) NOT NULL" \
                                            ");" \
                                            "\n" \
                                            "CREATE TABLE IF NOT EXISTS progress (" \
                                            "    uid INTEGER," \
                                            "    i INTEGER PRIMARY KEY," \
                                            "    anime_id TEXT NOT NULL," \
                                            "    title TEXT NOT NULL," \
                                            "    episodes_watched INTEGER DEFAULT 0," \
                                            "    FOREIGN KEY (uid) REFERENCES users(id)" \
                                            ");" \
                                            "\n" \
                                            "CREATE TABLE IF NOT EXISTS sessions (" \
                                            "    id VARCHAR(255) PRIMARY KEY,"
                                            "    uid INTEGER," \
                                            "    expires_at TEXT NOT NULL," \
                                            "    FOREIGN KEY (uid) REFERENCES users(id)" \
                                            ");";
                if (sqlite3_exec(db, create_table, NULL, NULL, NULL) != SQLITE_OK) {
                    for (int i = 0; i < num_params; i++) {
                        free(params[i].key);
                        free(params[i].value);
                    }
                    printf("Table creation failure: %s\n", sqlite3_errmsg(db));
                    send_file_to(conn, "500.html", NULL, num_params, params);
                    sqlite3_close(db);
                    sqlite3_finalize(stmt);
                    return NULL;
                }
                regex_t reg;

                char *username = search_keys_val_in("username", num_params, params);
                char *pwd = search_keys_val_in("pwd", num_params, params);
                char *confirm_pwd = search_keys_val_in("confirm_pwd", num_params, params);

                int username_len;
                int pwd_len;
                int err_happened = 0;
                if (!username || (username_len = strlen(username)) < 1 || username_len > 20) {
                    params[num_params].key = strdup("username_err");
                    params[num_params++].value = strdup("Invalid username length");
                    err_happened = 1;
                } else if (regcomp(&reg, "^[A-Za-z0-9_-]{1,20}$", REG_EXTENDED) == 0 && regexec(&reg, username, 0, NULL, 0) != 0) {
                    params[num_params].key = strdup("username_err");
                    params[num_params++].value = strdup("Only letters, numbers, underscores, and hyphens allowed");
                    err_happened = 1;
                } else {
                    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM users WHERE username = ?;", -1, &stmt, NULL) != SQLITE_OK) {
                        for (int i = 0; i < num_params; i++) {
                            free(params[i].key);
                            free(params[i].value);
                        }
                        printf("Statement preparation failure: %s\n", sqlite3_errmsg(db));
                        sqlite3_close(db);
                        sqlite3_finalize(stmt);
                        free(username);
                        free(pwd);
                        return NULL;
                    }
                    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
                    int num_users_with_that = 0;
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        num_users_with_that = sqlite3_column_int(stmt, 0);
                    }
                    if (num_users_with_that > 0) {
                        params[num_params].key = strdup("username_err");
                        params[num_params++].value = strdup("Username already taken");
                        err_happened = 1;
                    }
                    sqlite3_reset(stmt);
                }
                if (!pwd || (pwd_len = strlen(pwd)) < 15) {  // NOTE: require 15+ chars in pwd according to NIST, no sp. char requirement bc more char count more effective than requiring variety of sp. chars
                    params[num_params].key = strdup("pwd_err");
                    params[num_params++].value = strdup("Invalid password length");
                    err_happened = 1;
                }
                if (!confirm_pwd || (pwd && strcmp(pwd, confirm_pwd) != 0) || strcmp(confirm_pwd, "") == 0) {
                    params[num_params].key = strdup("confirm_err");
                    params[num_params++].value = strdup("Passwords don't match");
                    err_happened = 1;
                }
                if (err_happened) {
                    send_file_to(conn, "signup.html", NULL, num_params, params);
                } else {
                    const int hash_size = 32;
                    const int salt_size = 16;
                    const int encoded_size = 255;
                    uint8_t salt[salt_size];
                    char encoded_hash[encoded_size];
                    if (RAND_bytes(salt, salt_size) < 1) {
                        for (int i = 0; i < num_params; i++) {
                            free(params[i].key);
                            free(params[i].value);
                        }
                        sqlite3_close(db);
                        sqlite3_finalize(stmt);
                        err(__FILE__, __LINE__, NULL, 0);
                        return NULL;
                    }
                    argon2id_hash_encoded(1, 47104, 1, pwd, pwd_len, salt, salt_size, hash_size, encoded_hash, encoded_size);
                    if (sqlite3_prepare_v2(db, "INSERT INTO users (username, pwd_hash) VALUES (?, ?);", -1, &stmt, NULL) != SQLITE_OK) {
                        for (int i = 0; i < num_params; i++) {
                            free(params[i].key);
                            free(params[i].value);
                        }
                        printf("Statement preparation failure for signing up: %s\n", sqlite3_errmsg(db));
                        sqlite3_close(db);
                        sqlite3_finalize(stmt);
                        return NULL;
                    }
                    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt, 2, encoded_hash, -1, SQLITE_STATIC);
                    sqlite3_step(stmt);

                    send_file_to(conn, "login.html", NULL, num_params, params);
                }
                sqlite3_close(db);
                sqlite3_finalize(stmt);
            } else send_file_to(conn, "401.html", NULL, num_params, params);
        } else if (strncmp(url, "/login", 6) == 0 && consume_bucket(conn, 20)) {
            // 20 seconds to refill, punishes brute-forcers HARSHLY
            if (strcmp(session, "") == 0) {
                char *username = search_keys_val_in("username", num_params, params);
                char *pwd = search_keys_val_in("pwd", num_params, params);

                sqlite3 *db;
                sqlite3_stmt *stmt;

                if (sqlite3_open("data.db", &db) != SQLITE_OK || !username || !pwd) {
                    for (int i = 0; i < num_params; i++) {
                        free(params[i].key);
                        free(params[i].value);
                    }
                    err(__FILE__, __LINE__, url, 0);
                    return NULL;
                }

                if (sqlite3_prepare_v2(db, "SELECT username, pwd_hash FROM users WHERE username = ?;", -1, &stmt, NULL) != SQLITE_OK) {
                    free(url);
                    sqlite3_close(db);
                    for (int i = 0; i < num_params; i++) {
                        free(params[i].key);
                        free(params[i].value);
                    }
                    printf("Login preparation err: %s\n", sqlite3_errmsg(db));
                    params[num_params].key = strdup("server_err");
                    params[num_params++].value = strdup("Internal Server Error");
                    send_file_to(conn, "login.html", NULL, num_params, params);
                    return NULL;
                }

                if (sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK) {
                    free(url);
                    sqlite3_close(db);
                    sqlite3_finalize(stmt);
                    for (int i = 0; i < num_params; i++) {
                        free(params[i].key);
                        free(params[i].value);
                    }
                    printf("Login binding err: %s\n", sqlite3_errmsg(db));
                    params[num_params].key = strdup("server_err");
                    params[num_params++].value = strdup("Internal Server Error");
                    send_file_to(conn, "login.html", NULL, num_params, params);
                    return NULL;
                }
                sqlite3_step(stmt);
                const char *pwd_hash_encoded = (const char *) sqlite3_column_text(stmt, 1); // NOTE: .schema users; --> pwd_hash NOT NULL
                if (argon2id_verify(pwd_hash_encoded, pwd, strlen(pwd)) == ARGON2_OK) {
                    sqlite3_reset(stmt);
                    const int sid_size = 16;
                    const int double_size = sid_size * 2;
                    uint8_t session_id[sid_size];
                    char session_id_str[sid_size * 2];
                    session_id_str[0] = '\0';
                    int rand_status = RAND_priv_bytes(session_id, sid_size);
                    if (rand_status >= 1) for (int i = 0; i < sid_size; i++) sprintf(session_id_str, "%s%02x", session_id_str, session_id[i]);
                    if (rand_status < 1 || sqlite3_prepare_v2(db, "INSERT INTO sessions (id, uid, expires_at) SELECT ?, id, datetime('now', '+30 minutes') FROM users WHERE username = ?;", -1, &stmt, NULL) != SQLITE_OK
                                                                    || sqlite3_bind_text(stmt, 1, session_id_str, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC) != SQLITE_OK) {
                        free(url);
                        for (int i = 0; i < num_params; i++) {
                            free(params[i].key);
                            free(params[i].value);
                        }
                        params[num_params].key = strdup("server_err");
                        params[num_params++].value = strdup("Could not generate session");
                        send_file_to(conn, "login.html", NULL, num_params, params);

                        err(__FILE__, __LINE__, NULL, 0);
                        printf("Session generating err: %s\n", sqlite3_errmsg(db));
                        sqlite3_close(db);
                        sqlite3_finalize(stmt);
                        close_conn(conn);
                        return NULL;
                    }
                    sqlite3_step(stmt);
                    params[num_params].key = strdup("set_session");
                    params[num_params++].value = strdup(session_id_str);
                    send_file_to(conn, "index.html", NULL, num_params, params);
                } else {
                    params[num_params].key = strdup("invalid");
                    params[num_params++].value = strdup("Invalid Password");
                    send_file_to(conn, "login.html", NULL, num_params, params);
                }
                sqlite3_close(db);
                sqlite3_finalize(stmt);
            } else send_file_to(conn, "401.html", NULL, num_params, params);
        } else if (strncmp(url, "/logout", 7) == 0 && consume_bucket(conn, 10)) {
            if (strcmp(session, "") != 0) {
                sqlite3 *db;
                sqlite3_stmt *stmt;

                if (sqlite3_open("data.db", &db) != SQLITE_OK) {
                    err(__FILE__, __LINE__, url, 0);
                    printf("Logout err: %s\n", sqlite3_errmsg(db));
                    close_conn(conn);
                    return NULL;
                }
                if (sqlite3_prepare_v2(db, "DELETE FROM sessions WHERE id = ? AND uid = ?;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_text(stmt, 1, session, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_int(stmt, 2, uid) != SQLITE_OK) {
                    err(__FILE__, __LINE__, url, 0);
                    printf("Logout prep err: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);
                    sqlite3_finalize(stmt);
                    close_conn(conn);
                    return NULL;
                }
                sqlite3_step(stmt);
                printf("Latest logout err: %s\n", sqlite3_errmsg(db));

                pair set_session[1];
                set_session[0].key = strdup("set_session");
                set_session[0].value = strdup("");
                send_file_to(conn, "index.html", NULL, 1, set_session);
                send_file_to(conn, "index.html", NULL, num_params, params);

                sqlite3_close(db);
                sqlite3_finalize(stmt);
                free(set_session[0].key);
                free(set_session[0].value);
            } else send_file_to(conn, "401.html", NULL, num_params, params);
        } else if (strncmp(url, "/add", 4) == 0 && consume_bucket(conn, 3)) {
            char *anime_id = search_keys_val_in("anime_id", num_params, params);
            char *end;

            strtol(anime_id ? anime_id : "", &end, 10);

            char *title = search_keys_val_in("title", num_params, params);
            if (strcmp(session, "") != 0 && anime_id && anime_id != end && *end == '\0' && title) {
                sqlite3 *db;
                sqlite3_stmt *stmt;

                if (sqlite3_open("data.db", &db) != SQLITE_OK) {
                    free(url);
                    err(__FILE__, __LINE__, NULL, 0);
                    close_conn(conn);
                    return NULL;
                }

                if (sqlite3_prepare_v2(db, "INSERT INTO progress (uid, anime_id, title) SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM progress WHERE uid = ? AND anime_id = ?);", -1, &stmt, NULL) != SQLITE_OK) {
                    free(url);
                    err(__FILE__, __LINE__, NULL, 0);
                    printf("Adding anime prep err: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);
                    sqlite3_finalize(stmt);

                    char *res = http_res("{\"success\": false}", "application/json", 20, 200, "");
                    completely_send(conn, res, strlen(res) + 1);
                    free(res);
                    close_conn(conn);
                    return NULL;
                }

                if (sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK || sqlite3_bind_text(stmt, 2, anime_id, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_text(stmt, 3, title, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_int(stmt, 4, uid) != SQLITE_OK || sqlite3_bind_text(stmt, 5, anime_id, -1, SQLITE_STATIC) != SQLITE_OK) {
                    free(url);
                    err(__FILE__, __LINE__, NULL, 0);
                    printf("/add binding err: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);
                    sqlite3_finalize(stmt);

                    char *res = http_res("{\"success\": false}", "application/json", 20, 200, "");
                    completely_send(conn, res, strlen(res) + 1);
                    free(res);
                    close_conn(conn);
                    return NULL;
                }
                sqlite3_step(stmt);

                sqlite3_close(db);
                sqlite3_finalize(stmt);

                char *res = http_res("{\"success\": true}", "application/json", 19, 200, "");
                completely_send(conn, res, strlen(res) + 1);
                free(res);
            } else send_file_to(conn, "401.html", NULL, num_params, params);
        } else send_file_to(conn, "404.html", NULL, num_params, params);
    } else if (strncmp(r, "DELETE ", 7) == 0) {
        printf("%s\n", r);

        char *del_body = strstr(r, "\r\n\r\n") + 4;
        if (del_body && strcmp(del_body, "") != 0) {
            url_query_into_arr_pairs(del_body, &num_params, params);
        }
        if (strncmp(url, "/remove", 7) == 0 && consume_bucket(conn, 3)) {
            char *anime_id = search_keys_val_in("anime_id", num_params, params);
            char *end;
            strtol(anime_id ? anime_id : "", &end, 10);
            if (strcmp(session, "") != 0 && anime_id && anime_id != end && *end == '\0') {
                sqlite3 *db;
                sqlite3_stmt *stmt;

                if (sqlite3_open("data.db", &db) != SQLITE_OK) {
                    free(url);
                    err(__FILE__, __LINE__, NULL, 0);
                    close_conn(conn);
                    return NULL;
                }

                if (sqlite3_prepare_v2(db, "DELETE FROM progress WHERE uid = ? AND anime_id = ?;", -1, &stmt, NULL) != SQLITE_OK) {
                    free(url);
                    err(__FILE__, __LINE__, NULL, 0);
                    printf("Removing anime prep err: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);
                    sqlite3_finalize(stmt);

                    char *res = http_res("{\"success\": false}", "application/json", 20, 200, "");
                    completely_send(conn, res, strlen(res) + 1);
                    free(res);
                    close_conn(conn);
                    return NULL;
                }

                if (sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK || sqlite3_bind_text(stmt, 2, anime_id, -1, SQLITE_STATIC) != SQLITE_OK) {
                    free(url);
                    err(__FILE__, __LINE__, NULL, 0);
                    printf("/remove binding err: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);

                    char *res = http_res("{\"success\": false}", "application/json", 20, 200, "");
                    completely_send(conn, res, strlen(res) + 1);
                    free(res);
                    close_conn(conn);
                    return NULL;
                }
                sqlite3_step(stmt);

                sqlite3_close(db);
                sqlite3_finalize(stmt);

                char *res = http_res("{\"success\": true}", "application/json", 19, 200, "");
                completely_send(conn, res, strlen(res) + 1);
                free(res);
            } else send_file_to(conn, "401.html", NULL, num_params, params);
        } else send_file_to(conn, "404.html", NULL, num_params, params);
    } else if (strncmp(r, "PATCH", 5) == 0) {
        printf("%s\n", r);
        char *patch_body = strstr(r, "\r\n\r\n") + 4;
        if (patch_body && strcmp(patch_body, "") != 0) {
            url_query_into_arr_pairs(patch_body, &num_params, params);
        }
        if (strncmp(url, "/epwatched", 10) == 0 && consume_bucket(conn, 1)) {
            char *anime_id = search_keys_val_in("anime_id", num_params, params);
            char *ep_watched = search_keys_val_in("ep_watched", num_params, params);
            char *end, *ep_end;

            strtol(anime_id ? anime_id : "", &end, 10);
            int eps = strtol(ep_watched ? ep_watched : "", &ep_end, 10);
            if (strcmp(session, "") != 0 && anime_id && anime_id != end && *end == '\0' && ep_watched && ep_watched != ep_end && *ep_end == '\0') {
                sqlite3 *db;
                sqlite3_stmt *stmt;

                if (sqlite3_open("data.db", &db) != SQLITE_OK) {
                    free(url);
                    err(__FILE__, __LINE__, NULL, 0);
                    close_conn(conn);
                    return NULL;
                }

                if (sqlite3_prepare_v2(db, "UPDATE progress SET episodes_watched = ? WHERE uid = ? AND anime_id = ?;", -1, &stmt, NULL) != SQLITE_OK) {
                    free(url);
                    err(__FILE__, __LINE__, NULL, 0);
                    printf("/epwatched prep err: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);

                    char *res = http_res("{\"success\": false}", "application/json", 20, 200, "");
                    completely_send(conn, res, strlen(res) + 1);
                    free(res);
                    close_conn(conn);
                    return NULL;
                }

                if (sqlite3_bind_int(stmt, 1, eps) != SQLITE_OK || sqlite3_bind_int(stmt, 2, uid) != SQLITE_OK || sqlite3_bind_text(stmt, 3, anime_id, -1, SQLITE_STATIC) != SQLITE_OK) {
                    free(url);
                    err(__FILE__, __LINE__, NULL, 0);
                    printf("/epwatched binding err: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);
                    sqlite3_finalize(stmt);

                    char *res = http_res("{\"success\": false}", "application/json", 20, 200, "");
                    completely_send(conn, res, strlen(res) + 1);
                    free(res);
                    close_conn(conn);
                    return NULL;
                }
                sqlite3_step(stmt);

                sqlite3_close(db);
                sqlite3_finalize(stmt);

                char *res = http_res("{\"success\": true}", "application/json", 19, 200, "");
                completely_send(conn, res, strlen(res) + 1);
                free(res);
                close_conn(conn);
            } else send_file_to(conn, "401.html", NULL, num_params, params);
        } else send_file_to(conn, "404.html", NULL, num_params, params);
    } else send_file_to(conn, "404.html", NULL, num_params, params);
    for (int i = 0; i < num_params; i++) {
        free(params[i].key);
        free(params[i].value);
    }
    free(url);
    return NULL;
}

int main(void) {
    struct sockaddr_in ip_port;
    ip_port.sin_family = AF_INET;
    ip_port.sin_addr.s_addr = inet_addr("0.0.0.0");
    ip_port.sin_port = htons(8081); // TODO: Give user option to change port

    socklen_t t = sizeof(ip_port);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) err(__FILE__, __LINE__, NULL, 1);

    int reuse = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (bind(server_fd, (struct sockaddr *) &ip_port, t) == -1 || listen(server_fd, 10) == -1) {
        close(server_fd);
        err(__FILE__, __LINE__, NULL, 1);
    }

    printf("Listening on %s:%i\nStarted on %s at %s\n", inet_ntoa(ip_port.sin_addr), ntohs(ip_port.sin_port), __DATE__, __TIME__);

    SSL_library_init();
    OpenSSL_add_all_algorithms();

    sctx = SSL_CTX_new(TLS_server_method());
    ctx = SSL_CTX_new(TLS_client_method());
    if (!sctx || !ctx) {
        close(server_fd);
        err(__FILE__, __LINE__, NULL, 1);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (!SSL_CTX_set_min_proto_version(sctx, TLS1_2_VERSION) || SSL_CTX_set_default_verify_paths(ctx) < 1 || !SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        close(server_fd);
        SSL_CTX_free(sctx);
        SSL_CTX_free(ctx);
        err(__FILE__, __LINE__, NULL, 1);
    }

    uint64_t opts = SSL_OP_IGNORE_UNEXPECTED_EOF;
    opts |= SSL_OP_NO_RENEGOTIATION;
    opts |= SSL_OP_SERVER_PREFERENCE;
    SSL_CTX_set_options(sctx, opts);

    if (SSL_CTX_use_certificate_chain_file(sctx, "chain.pem") <= 0 || SSL_CTX_use_PrivateKey_file(sctx, "pkey.pem", SSL_FILETYPE_PEM) <= 0) {
        close(server_fd);
        SSL_CTX_free(sctx);
        SSL_CTX_free(ctx);
        err(__FILE__, __LINE__, NULL, 1);
    }
    SSL_CTX_set_session_id_context(sctx, (unsigned char *) "secure-socket-anime-list-server", 32);
    SSL_CTX_set_session_cache_mode(sctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_cache_size(sctx, 1024);
    SSL_CTX_set_timeout(sctx, 3600);
    SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, NULL);


    struct ip_entry *ip_entries;
    int ips = 0;

    ip_entries = malloc(sizeof(*ip_entries));
    if (ip_entries == NULL) {
        close(server_fd);
        SSL_CTX_free(ctx);
        err(__FILE__, __LINE__, NULL, 1);
    }

    epoll_fd = epoll_create(MAX_EVENTS);

    ev.data.fd = server_fd;
    ev.events = EPOLLIN;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1) {
        close(server_fd);
        close(epoll_fd);
        SSL_CTX_free(ctx);
        err(__FILE__, __LINE__, NULL, 1);
    }

    struct ip_entries_as_func_param rm_args;
    rm_args.entries = &ip_entries;
    rm_args.num_ips_ptr = &ips;

    pthread_mutex_init(&lock, NULL);

    pthread_t rm_exp_thr;
    pthread_create(&rm_exp_thr, NULL, rm_expired_sessions, &rm_args);
    pthread_detach(rm_exp_thr);

    while (1) {
        int wait;
        do {
            wait = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
            if (wait < 0) perror("epoll_wait");
        } while (wait < 0 && errno == EINTR);
        for (int i = 0; i < fd_size; i++) {
            if (events[i].data.fd == server_fd) {
                int cli = accept(server_fd, (struct sockaddr *) &ip_port, &t);
                SSL *ssl = SSL_new(sctx);
                if (cli == -1 || !ssl) {
                    err(__FILE__, __LINE__, NULL, 0);
                    close(cli);
                    if (ssl) {
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                    }
                    continue;
                }
                SSL_set_fd(ssl, cli);
                fcntl(cli, F_SETFL, O_NONBLOCK);

                struct connection *c = malloc(sizeof(connection));
                int acc = 0, cancel_cli = 0;

                while ((acc = SSL_accept(ssl)) <= 0) {
                    int error_code = SSL_get_error(ssl, acc);
                    if (error_code == SSL_ERROR_WANT_READ || error_code == SSL_ERROR_WANT_WRITE) {
                        continue;
                    } else {
                        //if (error_code == 1) ERR_print_errors_fp(stderr);
                        // NOTE: 8024DDF7FF7F0000:error:0A000416:SSL routines:ssl3_read_bytes:ssl/tls alert certificate             unknown:ssl/record/rec_layer_s3.c:918:SSL alert number 46
                        // Above prints as false positive from a client besides server device
                        cancel_cli = 1;
                        break;
                    }
                };
                if (cancel_cli) {
                    close(cli);
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    continue;
                }
                if (!c) {
                    err(__FILE__, __LINE__, NULL, 0);
                    close(cli);
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    continue;
                }
                c->fd = cli;

                struct sockaddr_in client_addr;
                socklen_t size = sizeof(struct sockaddr_in);
                if (getpeername(cli, (struct sockaddr *) &client_addr, &size) == -1) {
                    err(__FILE__, __LINE__, c, 0);
                    close(cli);
                    continue;
                }
                struct ip_entry *entry;
                int got_entry = 0;
                char *ip = inet_ntoa(client_addr.sin_addr);
                for (int i = 0, n = ips; i < n; i++) {
                    if (strcmp(ip_entries[i].ip, ip) == 0) {
                        entry = &(ip_entries[i]);
                        got_entry = 1;
                        break;
                    }
                }
                if (got_entry == 0) {
                    entry = malloc(sizeof(*entry));
                    if (entry == NULL) {
                        close(cli);
                        err(__FILE__, __LINE__, NULL, 0);
                        continue;
                    }
                    entry->ip = strdup(ip); // NOTE: must be freed
                    entry->active_connections = 0;

                    time_t now;
                    entry->bucket.fill_rate = 1; // tokens/sec;
                    entry->bucket.last_updated = time(&now);
                    entry->bucket.max_capacity = 100; // NOTE: Maximum requests/minute for most common req purpose: simple page navigation; multiple tokens consumed for pwd guessing/search queries
                    entry->bucket.tokens = 100;

                    struct ip_entry *tmp = realloc(ip_entries, (ips + 1) * sizeof(*ip_entries));
                    if (tmp == NULL) {
                        close(cli);
                        err(__FILE__, __LINE__, tmp, 0);
                        continue;
                    }
                    ip_entries = tmp;
                    ip_entries[ips] = *entry;
                    ips++;
                }
                c->entry_ptr = entry;
                c->ssl = ssl;
                c->port = ntohs(client_addr.sin_port);

                ev.events = EPOLLIN;
                ev.data.ptr = c;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cli, &ev) < 0) {
                    err(__FILE__, __LINE__, NULL, 0);
                    close(cli);
                    continue;
                }
                fd_size++;
                entry->active_connections++;
            } else {
                if (events[i].data.ptr && (connection *) events[i].data.ptr) {
                    pthread_mutex_lock(&lock);
                    handle(events[i].data.ptr);
                    pthread_mutex_unlock(&lock);
                }
            }
        }
    }
    pthread_mutex_destroy(&lock);
    close(server_fd);
    close(epoll_fd);
    for (int i = 0; i < ips; i++) {
        free(ip_entries[i].ip);
    }
    free(ip_entries);
    SSL_CTX_free(ctx);
    return 0;
}
