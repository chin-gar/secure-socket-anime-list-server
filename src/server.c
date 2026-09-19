#define MAX_HTTP_SIZE 16384
#define MAX_PARAMS 50
#define CHUNK_SIZE 4096
#define MAX_EVENTS 100
#define URL_CHAR_LIMIT 2000
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
#include <signal.h>
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

enum conn_state {
    TLS_HANDSHAKE,
    READING,
    PROCESSING,
    WRITING,
    CLOSING
};
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

typedef struct connection { // NOTE: Made to implement token bucket and pass properties such as ip addr and port
    int fd;
    uint16_t port; // NOTE: 2^16 = 65536 ports, including port 0
    struct ip_entry *entry_ptr;
    SSL *ssl;

    char req[MAX_HTTP_SIZE];
    size_t req_len;

    size_t sent_len, sent;
    char *buf;
    enum conn_state state;
} connection;

// NOTE: 1 on success; 0 on failure
int to_json_str_from_res(char **res_ptr) {
    char *no_header = strstr(*res_ptr, "\r\n\r\n");
    if (!no_header) return 0;
    no_header += 4;

    char *json = strchr(no_header, '{');
    if (!json) return 0;
    if (!strstr(*res_ptr, "Transfer-Encoding: chunked\r\n")) {
        char *json_dup = strdup(json);
        if (!json_dup) {
            err(__FILE__, __LINE__, NULL, 0);
            return 0;
        }
        *res_ptr = json_dup;
        return 1;
    }
    char *c_str = strndup(no_header, json - no_header);
    if (!c_str) {
        err(__FILE__, __LINE__, NULL, 0);
        return 0;
    }
    remove_spaces_btwn(c_str);

    char *h_end = NULL, *c_size_end = NULL;
    long hex = strtol(c_str, &h_end, 10);
    long c_size = strtol(c_str, &c_size_end, 16);
    if (*h_end != '\0' || h_end == c_str || c_size_end == c_str) {
        err(__FILE__, __LINE__, c_str, 0);
        return 0;
    }

    char sep[num_digits(c_size) + 5];
    char *new = strndup(json, c_size);
    if (!new || snprintf(sep, sizeof(sep), "\r\n%li\r\n", hex) < 0) {
        free(c_str);
        err(__FILE__, __LINE__, new, 0);
        return 0;
    }

    int index = c_size + strlen(sep);
    while (index < strlen(json)) {
        char *tmp_new = realloc(new, strlen(new) + c_size);
        if (!tmp_new) {
            free(c_str);
            err(__FILE__, __LINE__, new, 0);
            return 0;
        }
        strlcpy(&tmp_new[strlen(new)], &json[index], c_size + 1);
        new = tmp_new;
        index += (c_size + strlen(sep));
    }
    free(c_str);
    free(*res_ptr);
    *res_ptr = new;
    return 1;
}

// NOTE: Must be freed
char *http_req(const char *path, const char *host, const char *type, const char *additional) {
    if (additional == NULL) additional = "";
    int req_size = strlen(type) + 1 + strlen(path) + 17 + 19 + strlen(host) + 4 + strlen(additional) + 1;
    char *req = malloc(req_size);
    if (!req) {
        err(__FILE__, __LINE__, NULL, 0);
        return NULL;
    }
    int result = snprintf(req, req_size, "%s %s HTTP/1.1\r\nConnection: close\r\nHost: %s\r\n\r\n%s", type, path, host, additional) >= 0;
    if (result) return req;

    free(req);
    return NULL;
}

void close_conn(connection *conn) {
    if (!conn || !conn->entry_ptr) return;
    conn->entry_ptr->active_connections--;
    fd_size--;
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    if (conn->ssl) {
        //SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    close(conn->fd);
    conn->fd = -1;
    free(conn);
    conn = NULL;
}

int read_request(connection *conn) {
    size_t content_len = 0, header_len = 0;
    while (1) {
        size_t remaining = MAX_HTTP_SIZE - conn->req_len;
        size_t to_read = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;
        if (to_read <= 0 || (content_len > 0 && conn->req_len >= header_len + content_len)) break;

        size_t received = 0;
        int status = SSL_read_ex(conn->ssl, &conn->req[conn->req_len], to_read, &received);
        if (status == 1) {
            conn->req_len += received;

            if (conn->req_len >= 4 && strstr(conn->req, "\r\n\r\n") != NULL) {
                char *occ = NULL;
                if (content_len == 0 && (occ = strcasestr(conn->req, "Content-Length: "))) {
                    header_len = strlen(strstr(conn->req, "\r\n\r\n") - conn->req_len);
                    char *num_str = malloc(1), *end;
                    num_str[0] = '\0';

                    int i = occ - conn->req + 16;
                    while (conn->req[i] != '\r') {
                        char add[2] = {conn->req[i], '\0'};
                        heap_append(&num_str, add, strlen(num_str) + 2);
                        i++;
                    }

                    content_len = strtol(num_str, &end, 10);
                    if (*end == '\0' && end != num_str) {
                        continue;
                    }
                }
                return 1;
            }
            continue;
        }

        int err_code = SSL_get_error(conn->ssl, status);

        if (err_code == SSL_ERROR_WANT_READ) return 0;
        if (err_code == SSL_ERROR_WANT_WRITE) return -2;

        return -1;
    }
    if (conn->req_len <= 0 || strcmp(conn->req, "") == 0) {
        return -1;
    }
    return 1;
}


void queue_response(connection *conn, char *buf, const size_t len) {
    if (!conn || !conn->ssl || (SSL_get_shutdown(conn->ssl) & SSL_RECEIVED_SHUTDOWN) || conn->buf != NULL) return;
    //conn->buf = strndup(buf, len);
    conn->buf = buf;
    conn->sent_len = len;
    conn->sent = 0;
    conn->state = WRITING;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &(struct epoll_event) {
        .events = EPOLLOUT,
        .data.ptr = conn
    });
}

// NOTE: Must be freed
// TODO: Determine good max buffer length & modify read to read that
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
        if (connect(api_fd, it->ai_addr, it->ai_addrlen) != -1) break;
        close(api_fd);
    }
    freeaddrinfo(res);

    if (it != NULL) {
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            err(__FILE__, __LINE__, NULL, 0);
            close(api_fd);
            return NULL;
        }

        BIO *bio = BIO_new(BIO_s_socket());
        if (!bio) {
            err(__FILE__, __LINE__, NULL, 0);
            //SSL_shutdown(ssl);
            SSL_free(ssl);
            BIO_free(bio);
            close(api_fd);
            return NULL;
        }
        BIO_set_fd(bio, api_fd, BIO_CLOSE);
        SSL_set_bio(ssl, bio, bio);

        char *api_req = http_req(path, host, "GET", additional);

        char *buf = malloc(1);
        if (!SSL_set1_host(ssl, host) || !SSL_set_tlsext_host_name(ssl, host) || SSL_connect(ssl) != 1 || !api_req || !buf) {
            //SSL_shutdown(ssl);
            SSL_free(ssl);
            err(__FILE__, __LINE__, api_req, 0);
            free(buf);
            return NULL;
        }
        buf[0] = '\0';

        size_t written;
        SSL_write_ex(ssl, api_req, strlen(api_req), &written);
        free(api_req);

        int read_total = 0;
        while (1) {
            //printf("buf: %s\nnew size: %i\n", buf, read_total + CHUNK_SIZE + 1);
            char *tmp = realloc(buf, read_total + CHUNK_SIZE + 1);
            if (!tmp) {
                free(buf);
                buf = NULL;
                break;
            }
            size_t read;
            int status = SSL_read_ex(ssl, &tmp[read_total], CHUNK_SIZE, &read);
            if (status != 1) {
                buf = tmp;
                buf[read_total] = '\0';
                break;
            }
            read_total += read;
            tmp[read_total] = '\0';
            buf = tmp;
            if (read == 0) break;
        }
        //SSL_shutdown(ssl);
        SSL_free(ssl);
        close(api_fd);
        return buf;
    }
    return NULL;
}

// NOTE: Must be freed
char *http_res(const void *body, const char *type, const int content_len, int status, const char *more_header_info) {
    if (status <= 0) status = 200;
    if (more_header_info == NULL) more_header_info = "";

    char c_len_str[16 + num_digits(content_len) + 1];
    char c_type_str[14 + strlen(type) + 1];

    if (snprintf(c_len_str, sizeof(c_len_str), "Content-Length: %i", content_len) < 0 || snprintf(c_type_str, sizeof(c_type_str), "Content-Type: %s", type) < 0) {
        err(__FILE__, __LINE__, NULL, 0);
        return NULL;
    }

    int h_len = 21 + strlen(c_len_str) + strlen(c_type_str) + strlen(more_header_info) + (strlen(more_header_info) > 0 ? 2 : 0);
    int res_size = h_len + content_len + 1;
    char *res = malloc(res_size);
    if (!res || snprintf(res, h_len, "HTTP/1.1 %i\r\n%s\r\n%s\r\n%s\r\n", status, c_type_str, c_len_str, more_header_info) < 0 || (strlen(more_header_info) > 0 && snprintf(res + strlen(res), 3, "\r\n") < 0)) {
        err(__FILE__, __LINE__, NULL, 0);
        return NULL;
    }
    if (400 <= status && status < 600) {
        int current_len = strlen(res);
        return snprintf(res + current_len, 3, "\r\n") >= 0 ? res : NULL;
    } else if (strncmp(type, "text", 4) == 0 || strcmp(type, "application/json") == 0) {
        int current_len = strlen(res);
        return snprintf(res + current_len, res_size - current_len, "%s", (char *) body) >= 0 ? res : NULL;;
    } else {
        memcpy(res + h_len - 1, (uint8_t *) body, content_len);
    }
    return res;
}

// TODO: Determine if func needs to return int status code & if args[0] should become pair * & for no params to have to call NULL
// NOTE: args[0] = pair[]
void send_file_to(connection *conn, const char *name, const char *type, const int num_args, ...) {
    va_list args;
    va_start(args, num_args);

    pair *params = num_args > 0 ? va_arg(args, pair *) : NULL;
    va_end(args);
    if (type == NULL || strcmp(type, "") == 0) type = "text/html";

    char p_name[12 + strlen(name) + 1];
    if (snprintf(p_name, sizeof(p_name), "../frontend/%s", name) < 0) {
        err(__FILE__, __LINE__, NULL, 0);
        return;
    }

    size_t len = 0, status = 200;
    size_t total = 0, sent = 0;

    FILE *f = fopen(p_name, "rb");
    if (f) len = f_size(f);
    else status = 404;

    char *buf = malloc(len + 1);
    if (!buf) {
        if (f) fclose(f);
        err(__FILE__, __LINE__, NULL, 0);
        return;
    }

    if (f != NULL) {
        if (fread(buf, len, 1, f) < 0) status = 404;
        buf[len] = '\0';
        if (strcmp(type,"text/html") == 0) {
            char *tmp = rendered_template(buf, num_args, params);
            if (tmp) {
                free(buf);
                buf = tmp;
                len = strlen(buf);
            }
        }
        fclose(f);
    }

    char *sid = search_keys_val_in("set_session", num_args, params);
    char set_cookie[55 + (params && sid ? strlen(sid) : 0)];

    if (!sid || (sid && snprintf(set_cookie, sizeof(set_cookie), "Set-Cookie: session=%s; HttpOnly; SameSite=Lax; Secure", sid) < 0)) set_cookie[0] = '\0';

    char *res = http_res(buf, type, len, status, set_cookie);
    free(buf);
    if (!res) {
        err(__FILE__, __LINE__, sid, 0);
        return;
    }
    int res_len = strncmp(type, "text", 4) == 0 ? strlen(res) : len + strlen(res);
    for (int i = 0; i < (sid ? 2 : 1); i++) queue_response(conn, res, res_len); // NOTE: multiprint = temp workaround problem where epoll_wait hangs when HTTP req w/ set_session
    free(sid);
}

// NOTE: Must be freed
char *url_from_get_req(const char *req) {
    char *start = NULL;
    if (!req || !(start = strchr(req, '/'))) return NULL;
    const char *ex = strchr(start, ' ');
    return ex ? strndup(start, strlen(start) - strlen(ex)) : NULL;
}

int url_query_into_arr_pairs(const char *query_str, int *len_ptr, pair *p) {
    if (strcmp(query_str, "") == 0 || strcmp(query_str, "/") == 0 || !strchr(query_str, '=')) return 0;
    const char *question_marker = strchr(query_str, '?');
    char *queries = strdup(question_marker ? question_marker + 1 : query_str);
    if (!queries) return -1;

    char built[strlen(queries) + 1];
    built[0] = '\0';

    int building_key = 1;
    pair temp[1];
    temp[0].key = NULL;
    temp[0].value = NULL;
    for (int i = 0, n = strlen(queries); i < n && *len_ptr < MAX_PARAMS; i++) {
        int modified_temp = 0;
        if (building_key == 1 && queries[i] == '=') {
            temp[0].key = strdup(built);
            if (!temp[0].key) {
                err(__FILE__, __LINE__, queries, 0);
                free(temp[0].value);
                return -1;
            }
            decode(temp[0].key);
            memset(built, '\0', sizeof(built));
            building_key = 0;
            modified_temp = 1;
        }
        if (building_key == 0 && temp[0].key && (i == n - 1 || queries[i] == '&')) {
            if (i == n - 1) {
                char ch[2] = {queries[i], '\0'};
                if (!append(built, ch, strlen(built) + 2)) {
                    err(__FILE__, __LINE__, queries, 0);
                    free(temp[0].key);
                    free(temp[0].value);
                    return -1;
                }
            }
            building_key = 1;
            if ((temp[0].value = strdup(built))) decode(temp[0].value);
            if (!temp[0].value || safely_update_into_arr_pair(temp[0].key, temp[0].value, len_ptr, p, 0) < 1) {
                err(__FILE__, __LINE__, queries, 0);
                free(temp[0].key);
                free(temp[0].value);
                return -1;
            }
            memset(built, '\0', sizeof(built));
            temp[0].key = NULL;
            temp[0].value = NULL;
            modified_temp = 1;
        }
        if (modified_temp == 0) {
            char ch[2] = {queries[i], '\0'};
            if (!append(built, ch, strlen(built) + 2)) {
                err(__FILE__, __LINE__, queries, 0);
                free(temp[0].key);
                free(temp[0].value);
                return -1;
            }
        }
    }
    free(queries);
    free(temp[0].key);
    free(temp[0].value);
    return 1;
}

int min(int a, int b) {
    return a < b ? a : b;
}

// NOTE: 1 if consumed, 0 if ran out
int consume_bucket(connection *conn, const int num_tokens_to_consume) {
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
    struct ip_entry **ip_entries = params->entries;

    // TODO: Is opening data.db once and leaving it open gonna cause db access conflicts?
    sqlite3 *db = NULL;
    if (sqlite3_open("data.db", &db) != SQLITE_OK) {
        err(__FILE__, __LINE__, NULL, 0);
        printf("Error opening data.db for rm_exp_thr: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
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
            if (ip_entries[i]->active_connections <= 0 && difftime(mktime(gmtime(&now)), ip_entries[i]->last_connected) / 60 >= 30) {
                free(ip_entries[i]->ip);
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

void goto_index_html(connection *conn, int num_params, pair *params, const int uid) {
    char *buf = NULL;
    if (!(buf = recv_https_from_req("/api/edge/trending/anime?page[limit]=10", API_URL, "GET", NULL)) || !to_json_str_from_res(&buf) || safely_update_into_arr_pair("trending", buf, &num_params, params, 1) < 1) {
        send_file_to(conn, "index.html", NULL, num_params, params);
        err(__FILE__, __LINE__, buf, 0);
        return;
    }
    free(buf);

    char *session = NULL;
    char *set_session = NULL;
    if ((((session = search_keys_val_in("session", num_params, params)) && strcmp(session, "") != 0) || ((set_session = search_keys_val_in("set_session", num_params, params)) && strcmp(set_session, "") != 0)) && uid > 0) {
        sqlite3 *db = NULL;
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_open("data.db", &db) != SQLITE_OK || sqlite3_prepare_v2(db, "SELECT anime_id, episodes_watched FROM progress WHERE uid = ?;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK) {
            err(__FILE__, __LINE__, NULL, 0);
            if (safely_update_into_arr_pair("search_err", "Couldn't fetch results...", &num_params, params, 1) < 1) {
                send_file_to(conn, "500.html", NULL, num_params, params);
            } else send_file_to(conn, "search.html", NULL, num_params, params);
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return;
        }

        struct json_object *anime_list = json_object_new_object();
        while (anime_list && sqlite3_step(stmt) == SQLITE_ROW) {
            json_object_object_add(anime_list, (char *) sqlite3_column_text(stmt, 0), json_object_new_int(sqlite3_column_int(stmt, 1))); // 1st column guaranteed to not be NULL bc .schema progress;
        }
        if (json_object_object_length(anime_list) > 0) {
            safely_update_into_arr_pair("list", json_object_to_json_string_ext(anime_list, JSON_C_TO_STRING_NOSLASHESCAPE), &num_params, params, 1);
        }
        json_object_put(anime_list);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }
    send_file_to(conn, "index.html", NULL, num_params, params);
}

void *handle(void *arg) { // NOTE: arg = connection * of client data ptr
    connection *conn = (connection *) arg;
    SSL *ssl = conn->ssl;

    char *r = conn->req;

    size_t bytes = 0, received = 0;

    // conn->state = READING;
    // while (1) {
    //     size_t remaining = MAX_HTTP_SIZE - conn->req_len;
    //     size_t to_read = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;
    //     if (to_read <= 0) break;
    //
    //     int status = SSL_read_ex(ssl, &r[conn->req_len], to_read, &received);
    //     if (status > 0) {
    //         conn->req_len += received;
    //         r[conn->req_len] = '\0';
    //         continue;
    //     }
    //     int err_code = SSL_get_error(ssl, status);
    //     if (err_code == SSL_ERROR_WANT_READ) {
    //         epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &(struct epoll_event){
    //             .events = EPOLLIN,
    //             .data.ptr = conn
    //         });
    //         return NULL;
    //     } else if (err_code == SSL_ERROR_WANT_WRITE) {
    //         epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &(struct epoll_event){
    //             .events = EPOLLOUT,
    //             .data.ptr = conn
    //         });
    //         return NULL;
    //     }
    //     close_conn(conn);
    //     return NULL;
    // };
    // if (conn->req_len <= 0) {
    //     close_conn(conn);
    //     return NULL;
    // }
    time_t now = time(NULL);
    conn->entry_ptr->last_connected = mktime(gmtime(&now));

    pair params[MAX_PARAMS];
    int num_params = 0;

    char *url = NULL;

    // NOTE: Iterates thru header chars/properties JUST to look for session cookie FOR NOW
    // TODO: Build method & URL here
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
            if (snprintf(session + strlen(session), sizeof(session), "%c", r[i]) < 0) {
                err(__FILE__, __LINE__, NULL, 0);
                safely_update_into_arr_pair("err_reason", "Cannot fetch session right now", &num_params, params, 1);
                send_file_to(conn, "500.html", NULL, num_params, params);
                goto done;
            }
        }
    }
    int uid = -1;
    char *exp = NULL;

    if (strcmp(session, "") != 0) {
        decode(session);

        sqlite3 *db = NULL;
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_open("data.db", &db) != SQLITE_OK || sqlite3_prepare_v2(db, "SELECT uid, expires_at FROM sessions WHERE id = ? LIMIT 1;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_text(stmt, 1, session, -1, SQLITE_STATIC) != SQLITE_OK) {
            err(__FILE__, __LINE__, NULL, 0);
            printf("Finding session prep err: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            send_file_to(conn, "500.html", NULL, num_params, params);
            goto done;
        };
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            uid = sqlite3_column_int(stmt, 0);
            const unsigned char *column_txt = sqlite3_column_text(stmt, 1);
            exp = column_txt ? strdup((char *) column_txt) : NULL;
        }
        if (uid > 0 || exp != NULL) {
            struct tm exp_tm = {0};
            strptime(exp, "%Y-%m-%d %H:%M:%S", &exp_tm);
            free(exp);

            time_t exp_time_t = mktime(&exp_tm);

            time_t now = time(NULL);
            time_t gm_now = mktime(gmtime(&now));

            int diff = difftime(gm_now, exp_time_t) / 60;
            int expired = diff >= 0;

            sqlite3_reset(stmt);
            if (safely_update_into_arr_pair(expired ? "set_session" : "session", expired ? "" : session, &num_params, params, 1) < 1 || ((expired && (sqlite3_prepare_v2(db, "DELETE FROM sessions WHERE id = ?;", -1, &stmt, NULL) != SQLITE_OK)) || (!expired && sqlite3_prepare_v2(db, "UPDATE sessions SET expires_at = datetime('now', '+30 minutes') WHERE id = ?;", -1, &stmt, NULL) != SQLITE_OK)) || sqlite3_bind_text(stmt, 1, session, -1, SQLITE_STATIC) != SQLITE_OK) {
                err(__FILE__, __LINE__, NULL, 0);
                printf("Updating cli session err: %s\n", sqlite3_errmsg(db));
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                send_file_to(conn, "500.html", NULL, num_params, params);
                goto done;
            }
            sqlite3_step(stmt);
        } else {
            if (safely_update_into_arr_pair("set_session", "", &num_params, params, 1) < 1) {
                err(__FILE__, __LINE__, NULL, 0);
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                send_file_to(conn, "500.html", NULL, num_params, params);
                goto done;
            }
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }
    url = url_from_get_req(r);
    // TODO: Rethink if url char limit necessary and/or change anime search bar to match/drop req, considering encoded/decoded chars
    if (!url || strlen(url) > URL_CHAR_LIMIT) {
        char val[43 + num_digits(URL_CHAR_LIMIT) + 1];
        safely_update_into_arr_pair("err_reason", snprintf(val, sizeof(val), "Invalid URL or URL exceeds %i character limit", URL_CHAR_LIMIT) >= 0 ? val : "Invalid URL but can't fetch character limit", &num_params, params, 1);
        send_file_to(conn, "404.html", NULL, num_params, params);
        goto done;
    }
    if (strncmp(r, "GET ", 4) == 0) {
        if (url_query_into_arr_pairs(url, &num_params, params) == -1) {
            send_file_to(conn, "500.html", NULL, num_params, params);
            goto done;
        }
        // TODO: Set limit of num params to prevent function overload
        if (strcmp(url, "/") == 0 && consume_bucket(conn, 1)) {
            goto_index_html(conn, num_params, params, uid);
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
        } else if (strcmp(url, "/err_art.png") == 0) {
            send_file_to(conn, "err_art.png", "image/png", 0);
        } else if (strcmp(url, "/login") == 0 && consume_bucket(conn, 3)) {
            if (strcmp(session, "") == 0)
                send_file_to(conn, "login.html", NULL, num_params, params);
            else send_file_to(conn, "401.html", NULL, num_params, params);
        } else if ((strncmp(url, "/search?filter%5Btext%5D=", 25) == 0 || strncmp(url, "/search?filter[text]=", 21) == 0) && consume_bucket(conn, 5)) {
            char *title = NULL;
            int t_len_exceeded = -1;
            if (!(title = search_keys_val_in("filter[text]", num_params, params)) || (t_len_exceeded = (strlen(title) > 300))) {
                if (t_len_exceeded == 1) safely_update_into_arr_pair("err_reason", "Title is too long", &num_params, params, 1);
                send_file_to(conn, "400.html", NULL, num_params, params);
                goto done;
            }

            char search_url[15 + strlen(&url[7]) + 1];
            char *buf = NULL;
            if (snprintf(search_url, sizeof(search_url), "/api/edge/anime%s", strcmp(&url[21], "") != 0 ? &url[7] : "") < 0 || !(buf = recv_https_from_req(search_url, API_URL, "GET", NULL)) || !to_json_str_from_res(&buf) || safely_update_into_arr_pair("results", buf, &num_params, params, 1) < 1) {
                if (safely_update_into_arr_pair("search_err", "Couldn't fetch results...", &num_params, params, 1) < 1) {
                    send_file_to(conn, "500.html", NULL, num_params, params);
                } else send_file_to(conn, "search.html", NULL, num_params, params);
                err(__FILE__, __LINE__, buf, 0);
                goto done;
            }
            free(buf);

            if (strcmp(session, "") != 0 && uid > 0) {
                sqlite3 *db = NULL;
                sqlite3_stmt *stmt = NULL;
                if (sqlite3_open("data.db", &db) != SQLITE_OK || sqlite3_prepare_v2(db, "SELECT anime_id, episodes_watched FROM progress WHERE uid = ?;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK) {
                    err(__FILE__, __LINE__, NULL, 0);
                    if (safely_update_into_arr_pair("search_err", "Couldn't fetch results...", &num_params, params, 1) < 1) {
                        send_file_to(conn, "500.html", NULL, num_params, params);
                    } else send_file_to(conn, "search.html", NULL, num_params, params);
                    sqlite3_finalize(stmt);
                    sqlite3_close(db);
                    goto done;
                }

                struct json_object *anime_list = json_object_new_object();
                while (anime_list && sqlite3_step(stmt) == SQLITE_ROW) {
                    json_object_object_add(anime_list, (char *) sqlite3_column_text(stmt, 0), json_object_new_int(sqlite3_column_int(stmt, 1))); // 1st column guaranteed to not be NULL bc .schema progress;
                }
                if (json_object_object_length(anime_list) > 0) {
                    safely_update_into_arr_pair("list", json_object_to_json_string_ext(anime_list, JSON_C_TO_STRING_NOSLASHESCAPE), &num_params, params, 1);
                }
                json_object_put(anime_list);
                sqlite3_finalize(stmt);
                sqlite3_close(db);
            }
            send_file_to(conn, "search.html", NULL, num_params, params);
        } else if (strncmp(url, "/list", 5) == 0 && consume_bucket(conn, 3)) {
            if (strcmp(session, "") != 0 && uid > 0) {
                int page = 1;
                if (strncmp(url, "/list?", 6) != 0 && strcmp(url, "/list") != 0) {
                    send_file_to(conn, "400.html", NULL, num_params, params);
                    goto done;
                }
                char *end;
                char *p_str = search_keys_val_in("page", num_params, params);
                if (p_str) page = strtol(p_str ? p_str : "", &end, 10);
                if (p_str && (p_str == end || *end != '\0' || page < 1)) {
                    free(p_str);
                    safely_update_into_arr_pair("err_reason", "Invalid page number.", &num_params, params, 1);
                    send_file_to(conn, "400.html", NULL, num_params, params);
                    goto done;
                }
                free(p_str);
                sqlite3 *db = NULL;
                sqlite3_stmt *stmt = NULL;

                if (sqlite3_open("data.db", &db) != SQLITE_OK) {
                    err(__FILE__, __LINE__, NULL, 0);
                    printf("Opening db for list err: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);
                    send_file_to(conn, "500.html", NULL, num_params, params);
                    goto done;
                }
                const int offset = (page - 1) * 20;
                char *title = search_keys_val_in("q", num_params, params);
                char pattern[title ? (strlen(title) + 2 + 1) : 1];
                pattern[0] = '\0';

                int step = -1;
                if ((title && snprintf(pattern, sizeof(pattern), "%%%s%%", title) < 0) || (title ? (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM (SELECT * FROM progress WHERE uid = ? AND title LIKE ? ORDER BY i DESC LIMIT 20 OFFSET ?);", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK || sqlite3_bind_text(stmt, 2, pattern, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_int(stmt, 3, offset) != SQLITE_OK) : (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM (SELECT * FROM progress WHERE uid = ? ORDER BY i DESC LIMIT 20 OFFSET ?);", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK || sqlite3_bind_int(stmt, 2, offset) != SQLITE_OK)) || ((step = sqlite3_step(stmt)) != SQLITE_ROW && step != SQLITE_DONE)) {
                    err(__FILE__, __LINE__, NULL, 0);
                    printf("List # prep err: %s\n", sqlite3_errmsg(db));
                    sqlite3_finalize(stmt);
                    sqlite3_close(db);
                    send_file_to(conn, "500.html", NULL, num_params, params);
                    goto done;
                }
                int size = sqlite3_column_int(stmt, 0);
                sqlite3_reset(stmt);

                if (title ? (sqlite3_prepare_v2(db, "SELECT anime_id, episodes_watched FROM progress WHERE uid = ? AND title LIKE ? ORDER BY i DESC LIMIT 20 OFFSET ?;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK || sqlite3_bind_text(stmt, 2, pattern, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_int(stmt, 3, offset) != SQLITE_OK) : (sqlite3_prepare_v2(db, "SELECT anime_id, episodes_watched FROM progress WHERE uid = ? ORDER BY i DESC LIMIT 20 OFFSET ?;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK || sqlite3_bind_int(stmt, 2, offset) != SQLITE_OK)) {
                    err(__FILE__, __LINE__, NULL, 0);
                    printf("List prep err: %s\n", sqlite3_errmsg(db));
                    sqlite3_finalize(stmt);
                    sqlite3_close(db);
                    send_file_to(conn, "500.html", NULL, num_params, params);
                    goto done;
                }

                json_object *arr = json_object_new_array_ext(size);
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char *anime_id = (char *) sqlite3_column_text(stmt, 0); // NOTE: NOT NULL bc db .schema
                    const int episodes_watched = sqlite3_column_int(stmt, 1);

                    json_object *item = json_object_new_object();
                    json_object *ep_obj = json_object_new_int(episodes_watched);

                    char endpt[16 + strlen(anime_id) + 1];
                    if (!item || !ep_obj || snprintf(endpt, sizeof(endpt), "/api/edge/anime/%s", anime_id) < 0) {
                        json_object_put(item);
                        json_object_put(ep_obj);
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
                char *json_str = NULL;
                if (arr && (json_str = (char *) json_object_to_json_string_ext(arr, JSON_C_TO_STRING_NOSLASHESCAPE)) && safely_update_into_arr_pair("list", json_str, &num_params, params, 1)) {
                    send_file_to(conn, "list.html", NULL, num_params, params);
                    json_object_put(arr);
                } else {
                    err(__FILE__, __LINE__, NULL, 0);
                    send_file_to(conn, "500.html", NULL, num_params, params);
                }

                sqlite3_finalize(stmt);
                sqlite3_close(db);
            } else send_file_to(conn, "401.html", NULL, num_params, params);
        } else send_file_to(conn, "404.html", NULL, num_params, params);
    } else if (strncmp(r, "POST ", 5) == 0) {
        char *sep = strstr(r, "\r\n\r\n");
        char *post_body = sep ? sep + 4 : NULL;
        // TODO: How should post & other req method errs be handled? What should they return?
        if (post_body && strcmp(post_body, "") != 0) {
            url_query_into_arr_pairs(post_body, &num_params, params);
        }
        if (strncmp(url, "/signup", 7) == 0 && consume_bucket(conn, 5)) {
            if (strcmp(session, "") == 0) {
                sqlite3 *db = NULL;
                sqlite3_stmt *stmt = NULL; // NOTE: Prepared statement to prevent SQL injection atks

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
                if (sqlite3_open("data.db", &db) != SQLITE_OK || sqlite3_exec(db, create_table, NULL, NULL, NULL) != SQLITE_OK) {
                    err(__FILE__, __LINE__, NULL, 0);
                    printf("Table creation failure: %s\n", sqlite3_errmsg(db));
                    send_file_to(conn, "500.html", NULL, num_params, params);
                    sqlite3_close(db);
                    goto done;
                }
                regex_t reg;

                char *username = search_keys_val_in("username", num_params, params);
                char *pwd = search_keys_val_in("pwd", num_params, params);
                char *confirm_pwd = search_keys_val_in("confirm_pwd", num_params, params);

                int username_len = 0;
                int pwd_len = 0;
                int err_happened = 0;
                if (!username || (username_len = strlen(username)) < 1 || username_len > 20) {
                    safely_update_into_arr_pair("username_err", "Invalid username length", &num_params, params, 1);
                    err_happened = 1;
                } else if (regcomp(&reg, "^[A-Za-z0-9_-]{1,20}$", REG_EXTENDED) == 0 && regexec(&reg, username, 0, NULL, 0) != 0) {
                    safely_update_into_arr_pair("username_err", "Only letters, numbers, underscores, and hyphens allowed", &num_params, params, 1);
                    err_happened = 1;
                } else {
                    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM users WHERE username = ?;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK) {
                        err(__FILE__, __LINE__, NULL, 0);
                        printf("Lookup users prep failure: %s\n", sqlite3_errmsg(db));
                        safely_update_into_arr_pair("username_err", "Server-side username lookup error", &num_params, params, 1);
                        err_happened = 1;
                    } else {
                        int num_users_with_that = 0;
                        while (sqlite3_step(stmt) == SQLITE_ROW) {
                            num_users_with_that = sqlite3_column_int(stmt, 0);
                        }
                        if (num_users_with_that > 0) {
                            safely_update_into_arr_pair("username_err", "Username already taken", &num_params, params, 1);
                            err_happened = 1;
                        }
                        sqlite3_reset(stmt);
                    }
                }
                if (!pwd || (pwd_len = strlen(pwd)) < 15) {  // NOTE: require 15+ chars in pwd according to NIST, no sp. char requirement bc more char count more effective than requiring variety of sp. chars
                    safely_update_into_arr_pair("pwd_err", "Invalid password length", &num_params, params, 1);
                    err_happened = 1;
                }
                if (!confirm_pwd || (pwd && strcmp(pwd, confirm_pwd) != 0) || strcmp(confirm_pwd, "") == 0) {
                    safely_update_into_arr_pair("confirm_err", "Passwords don't match", &num_params, params, 1);
                    err_happened = 1;
                }
                free(confirm_pwd);
                if (err_happened) {
                    send_file_to(conn, "signup.html", NULL, num_params, params);
                } else {
                    const int hash_size = 32;
                    const int salt_size = 16;
                    const int encoded_size = 255;

                    uint8_t salt[salt_size];
                    char encoded_hash[encoded_size];

                    if (RAND_bytes(salt, salt_size) < 1) {
                        err(__FILE__, __LINE__, username, 0);
                        OPENSSL_cleanse(pwd, strlen(pwd));
                        free(pwd);
                        sqlite3_finalize(stmt);
                        sqlite3_close(db);
                        goto done;
                    }

                    int encoded_status = argon2id_hash_encoded(1, 47104, 1, pwd, pwd_len, salt, salt_size, hash_size, encoded_hash, encoded_size);
                    if (encoded_status != ARGON2_OK) {
                        err(__FILE__, __LINE__, username, 0);
                        OPENSSL_cleanse(pwd, strlen(pwd));
                        free(pwd);
                        printf("argon2id encoded hash failure: %s\n", argon2_error_message(encoded_status));
                        sqlite3_finalize(stmt);
                        sqlite3_close(db);
                        goto done;
                    }

                    if (sqlite3_prepare_v2(db, "INSERT INTO users (username, pwd_hash) VALUES (?, ?);", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_text(stmt, 2, encoded_hash, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_step(stmt) != SQLITE_DONE) {
                        err(__FILE__, __LINE__, username, 0);
                        OPENSSL_cleanse(pwd, strlen(pwd));
                        free(pwd);
                        printf("Statement preparation failure for signing up: %s\n", sqlite3_errmsg(db));
                        sqlite3_finalize(stmt);
                        sqlite3_close(db);
                        goto done;
                    }
                    send_file_to(conn, "login.html", NULL, num_params, params);
                }
                free(username);
                OPENSSL_cleanse(pwd, strlen(pwd));
                free(pwd);
                sqlite3_finalize(stmt);
                sqlite3_close(db);
            } else send_file_to(conn, "401.html", NULL, num_params, params);
        } else if (strncmp(url, "/login", 6) == 0 && consume_bucket(conn, 20)) {
            // 20 seconds to refill, punishes brute-forcers HARSHLY
            if (strcmp(session, "") == 0) {
                char *username = search_keys_val_in("username", num_params, params);
                char *pwd = search_keys_val_in("pwd", num_params, params);

                sqlite3 *db = NULL;
                sqlite3_stmt *stmt = NULL;

                int db_open_failed = sqlite3_open("data.db", &db) != SQLITE_OK;
                if (db_open_failed || !username || !pwd || sqlite3_prepare_v2(db, "SELECT username, pwd_hash FROM users WHERE username = ?;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK) {
                    err(__FILE__, __LINE__, username, 0);
                    free(pwd);
                    printf("Login preparation err: %s\n", sqlite3_errmsg(db));
                    sqlite3_finalize(stmt);
                    sqlite3_close(db);
                    safely_update_into_arr_pair("server_err", "Internal Server Error", &num_params, params, 1);
                    send_file_to(conn, "login.html", NULL, num_params, params);
                    goto done;
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
                    int ses_append_status = -1;
                    if (rand_status >= 1) {
                        for (int i = 0; i < sid_size; i++) {
                            size_t ses_len = strlen(session_id_str);
                            if ((ses_append_status = snprintf(session_id_str + ses_len, sizeof(session_id_str) - ses_len, "%02x", session_id[i])) < 0) break;
                        }
                    }
                    if (rand_status < 1 || ses_append_status < 0 || sqlite3_prepare_v2(db, "SELECT id FROM users WHERE username = ? LIMIT 1;", -1, &stmt, NULL) || sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_step(stmt) != SQLITE_ROW || (uid = sqlite3_column_int(stmt, 0)) < 0 || sqlite3_reset(stmt) != SQLITE_OK || sqlite3_prepare_v2(db, "INSERT INTO sessions (id, uid, expires_at) SELECT ?, id, datetime('now', '+30 minutes') FROM users WHERE username = ?;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_text(stmt, 1, session_id_str, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_step(stmt) != SQLITE_DONE || safely_update_into_arr_pair("set_session", session_id_str, &num_params, params, 1) < 1) {
                        err(__FILE__, __LINE__, username, 0);
                        free(pwd);
                        printf("Session generating err: %s\n", sqlite3_errmsg(db));
                        sqlite3_finalize(stmt);
                        sqlite3_close(db);
                        safely_update_into_arr_pair("server_err", "Could not generate session", &num_params, params, 1);
                        send_file_to(conn, "login.html", NULL, num_params, params);
                        goto done;
                    }
                    goto_index_html(conn, num_params, params, uid);
                } else {
                    safely_update_into_arr_pair("invalid", "Invalid Password", &num_params, params, 1);
                    send_file_to(conn, "login.html", NULL, num_params, params);
                }
                free(username);
                free(pwd);
                sqlite3_finalize(stmt);
                sqlite3_close(db);
            } else send_file_to(conn, "401.html", NULL, num_params, params);
        } else if (strncmp(url, "/logout", 7) == 0 && consume_bucket(conn, 10)) {
            if (strcmp(session, "") != 0) {
                sqlite3 *db = NULL;
                sqlite3_stmt *stmt = NULL;

                if (sqlite3_open("data.db", &db) != SQLITE_OK || sqlite3_prepare_v2(db, "DELETE FROM sessions WHERE id = ? AND uid = ?;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_text(stmt, 1, session, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_int(stmt, 2, uid) != SQLITE_OK || sqlite3_step(stmt) != SQLITE_DONE) {
                    err(__FILE__, __LINE__, NULL, 0);
                    printf("Logout err: %s\n", sqlite3_errmsg(db));
                    sqlite3_finalize(stmt);
                    sqlite3_close(db);
                    char *res = http_res("{\"success\": false}", "application/json", 20, 200, "");
                    queue_response(conn, res, strlen(res));
                    goto done;
                }
                sqlite3_finalize(stmt);
                sqlite3_close(db);

                pair set_session[1];
                int set_ses_pair_len = 0;
                safely_update_into_arr_pair("set_session", "", &set_ses_pair_len, set_session, 1);

                goto_index_html(conn, 1, set_session, uid);
                goto_index_html(conn, num_params, params, -1);

                free(set_session[0].key);
                free(set_session[0].value);
            } else send_file_to(conn, "401.html", NULL, num_params, params);
        } else if (strncmp(url, "/add", 4) == 0 && consume_bucket(conn, 3)) {
            char *anime_id = search_keys_val_in("anime_id", num_params, params);
            char *end;

            strtol(anime_id ? anime_id : "", &end, 10);

            char *title = search_keys_val_in("title", num_params, params);
            if (strcmp(session, "") != 0 && anime_id && anime_id != end && *end == '\0' && title) {
                sqlite3 *db = NULL;
                sqlite3_stmt *stmt = NULL;

                if (sqlite3_open("data.db", &db) != SQLITE_OK || sqlite3_prepare_v2(db, "INSERT INTO progress (uid, anime_id, title) SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM progress WHERE uid = ? AND anime_id = ?);", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK || sqlite3_bind_text(stmt, 2, anime_id, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_text(stmt, 3, title, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_bind_int(stmt, 4, uid) != SQLITE_OK || sqlite3_bind_text(stmt, 5, anime_id, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_step(stmt) != SQLITE_DONE) {
                    err(__FILE__, __LINE__, NULL, 0);
                    printf("/add prep err: %s\n", sqlite3_errmsg(db));
                    sqlite3_finalize(stmt);
                    sqlite3_close(db);

                    char *res = http_res("{\"success\": false}", "application/json", 18, 200, "");
                    queue_response(conn, res, strlen(res));
                    goto done;
                }

                sqlite3_finalize(stmt);
                sqlite3_close(db);

                char *res = http_res("{\"success\": true}", "application/json", 17, 200, "");
                queue_response(conn, res, strlen(res));
            } else send_file_to(conn, "401.html", NULL, num_params, params);
        } else send_file_to(conn, "404.html", NULL, num_params, params);
    } else if (strncmp(r, "DELETE ", 7) == 0) {
        char *sep = strstr(r, "\r\n\r\n");
        char *del_body = sep ? sep + 4 : NULL;
        if (del_body && strcmp(del_body, "") != 0) {
            url_query_into_arr_pairs(del_body, &num_params, params);
        }
        if (strncmp(url, "/remove", 7) == 0 && consume_bucket(conn, 3)) {
            char *anime_id = search_keys_val_in("anime_id", num_params, params);
            char *end;
            strtol(anime_id ? anime_id : "", &end, 10);
            if (strcmp(session, "") != 0 && anime_id && anime_id != end && *end == '\0') {
                sqlite3 *db = NULL;
                sqlite3_stmt *stmt = NULL;

                if (sqlite3_open("data.db", &db) != SQLITE_OK || sqlite3_prepare_v2(db, "DELETE FROM progress WHERE uid = ? AND anime_id = ?;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int(stmt, 1, uid) != SQLITE_OK || sqlite3_bind_text(stmt, 2, anime_id, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_step(stmt) != SQLITE_DONE) {
                    err(__FILE__, __LINE__, NULL, 0);
                    printf("/remove prep err: %s\n", sqlite3_errmsg(db));
                    sqlite3_finalize(stmt);
                    sqlite3_close(db);

                    char *res = http_res("{\"success\": false}", "application/json", 18, 200, "");
                    queue_response(conn, res, strlen(res));
                    goto done;
                }
                sqlite3_finalize(stmt);
                sqlite3_close(db);

                char *res = http_res("{\"success\": true}", "application/json", 17, 200, "");
                queue_response(conn, res, strlen(res));
            } else send_file_to(conn, "401.html", NULL, num_params, params);
        } else send_file_to(conn, "404.html", NULL, num_params, params);
    } else if (strncmp(r, "PATCH", 5) == 0) {
        char *sep = strstr(r, "\r\n\r\n");
        char *patch_body = sep ? sep + 4 : NULL;
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
                sqlite3 *db = NULL;
                sqlite3_stmt *stmt = NULL;

                if (sqlite3_open("data.db", &db) != SQLITE_OK || sqlite3_prepare_v2(db, "UPDATE progress SET episodes_watched = ? WHERE uid = ? AND anime_id = ?;", -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int(stmt, 1, eps) != SQLITE_OK || sqlite3_bind_int(stmt, 2, uid) != SQLITE_OK || sqlite3_bind_text(stmt, 3, anime_id, -1, SQLITE_STATIC) != SQLITE_OK || sqlite3_step(stmt) != SQLITE_DONE) {
                    err(__FILE__, __LINE__, NULL, 0);
                    printf("/epwatched prep err: %s\n", sqlite3_errmsg(db));
                    sqlite3_finalize(stmt);
                    sqlite3_close(db);

                    char *res = http_res("{\"success\": false}", "application/json", 18, 200, "");
                    queue_response(conn, res, strlen(res));
                    goto done;
                }
                sqlite3_finalize(stmt);
                sqlite3_close(db);

                char *res = http_res("{\"success\": true}", "application/json", 17, 200, "");
                queue_response(conn, res, strlen(res));
            } else send_file_to(conn, "401.html", NULL, num_params, params);
        } else send_file_to(conn, "404.html", NULL, num_params, params);
    } else send_file_to(conn, "404.html", NULL, num_params, params);
    done:
    for (int i = 0; i < num_params; i++) {
        free(params[i].key);
        free(params[i].value);
    }
    free(url);
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
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

    struct ip_entry **ip_entries;
    int ips = 0;

    if (!(ip_entries = malloc(sizeof(*ip_entries)))) {
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
    rm_args.entries = ip_entries;
    rm_args.num_ips_ptr = &ips;

    pthread_mutex_init(&lock, NULL);

    pthread_t rm_exp_thr;
    pthread_create(&rm_exp_thr, NULL, rm_expired_sessions, &rm_args);
    pthread_detach(rm_exp_thr);

    while (1) {
        int wait;
        do {
            wait = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        } while (wait < 0 && errno == EINTR);
        for (int i = 0; i < wait; i++) {
            if (events[i].data.fd == server_fd) {
                int cli = accept(server_fd, (struct sockaddr *) &ip_port, &t);
                if (cli == -1) {
                    err(__FILE__, __LINE__, NULL, 0);
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    sleep(1);
                    continue;
                }
                fcntl(cli, F_SETFL, O_NONBLOCK);

                SSL *ssl = SSL_new(sctx);
                if (!ssl) {
                    close(cli);
                    continue;
                }

                SSL_set_fd(ssl, cli);

                struct connection *c = calloc(1, sizeof(connection));
                int acc = 0, cancel_cli = 0;

                if (!c) {
                    err(__FILE__, __LINE__, NULL, 0);
                    close(cli);
                    //SSL_shutdown(ssl);
                    SSL_free(ssl);
                    ssl = NULL;
                    continue;
                }

                c->state = TLS_HANDSHAKE;
                c->fd = cli;
                c->ssl = ssl;

                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cli, &(struct epoll_event) {
                    .events = EPOLLIN,
                    .data.ptr = c
                });
                int cont = 0;
                while ((acc = SSL_accept(ssl)) <= 0) {
                    int error_code = SSL_get_error(ssl, acc);
                    if (error_code == SSL_ERROR_WANT_READ) {
                        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, cli, &(struct epoll_event){
                            .events = EPOLLIN,
                            .data.ptr = c
                        });
                        //cont = 1;
                        break;
                    } else if (error_code == SSL_ERROR_WANT_WRITE) {
                        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, cli, &(struct epoll_event){
                            .events = EPOLLOUT,
                            .data.ptr = c
                        });
                        //cont = 1;
                        break;
                    } else {
                        cancel_cli = 1;
                        break;
                    }
                }
                if (cont) continue;
                if (cancel_cli) {
                    close(cli);
                    //SSL_shutdown(ssl);
                    SSL_free(ssl);
                    ssl = NULL;
                    continue;
                }

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
                    if (strcmp(ip_entries[i]->ip, ip) == 0) {
                        entry = ip_entries[i];
                        got_entry = 1;
                        break;
                    }
                }
                if (got_entry == 0) {
                    entry = malloc(sizeof(*entry));
                    if (!entry || !(entry->ip = strdup(ip))) {
                        close(cli);
                        err(__FILE__, __LINE__, NULL, 0);
                        continue;
                    }
                    entry->active_connections = 0;

                    time_t now;
                    entry->bucket.fill_rate = 1; // tokens/sec;
                    entry->bucket.last_updated = time(&now);
                    entry->bucket.max_capacity = 100; // NOTE: Maximum requests/minute for most common req purpose: simple page navigation; multiple tokens consumed for pwd guessing/search queries
                    entry->bucket.tokens = 100;

                    struct ip_entry **tmp = realloc(ip_entries, (ips + 1) * sizeof(*ip_entries));
                    if (!tmp) {
                        close(cli);
                        err(__FILE__, __LINE__, tmp, 0);
                        continue;
                    }
                    ip_entries = tmp;
                    ip_entries[ips++] = entry;
                }
                c->entry_ptr = entry;
                c->port = ntohs(client_addr.sin_port);

                c->req[0] = '\0';
                c->req_len = 0;
                c->buf = NULL;
                c->state = READING;

                fd_size++;
                entry->active_connections++;
            } else {
                connection *conn = NULL;
                if (events[i].data.ptr && (conn = (connection *) events[i].data.ptr)) {
                    if (events[i].events & EPOLLIN) {
                        int result = read_request(conn);

                        if (result == 0) {
                            // Need more network data.
                            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &(struct epoll_event) {
                                .events = EPOLLIN,
                                .data.ptr = conn
                            });
                            continue;
                        }

                        if (result == -2) {
                            // TLS needs to write.
                            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &(struct epoll_event) {
                                .events = EPOLLOUT,
                                .data.ptr = conn
                            });
                            continue;
                        }

                        if (result < 0) {
                            close_conn(conn);
                            continue;
                        }
                        conn->state = PROCESSING;
                        handle(events[i].data.ptr);
                        continue;
                    }
                    if (events[i].events & EPOLLOUT) {
                        size_t sent = 0;
                        int cont = 0;
                        while (conn->sent < conn->sent_len) {
                            int status = SSL_write_ex(conn->ssl, &conn->buf[conn->sent], conn->sent_len - conn->sent, &sent);
                            if (status > 0) {
                                conn->sent += sent;
                                continue;
                            }
                            int err_code = SSL_get_error(conn->ssl, status);
                            if (err_code == SSL_ERROR_WANT_READ) {
                                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &(struct epoll_event){
                                    .events = EPOLLIN,
                                    .data.ptr = conn
                                });
                                cont = 1;
                                break;
                            } else if (err_code == SSL_ERROR_WANT_WRITE) {
                                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &(struct epoll_event){
                                    .events = EPOLLOUT,
                                    .data.ptr = conn
                                });
                                cont = 1;
                                break;
                            }
                            cont = 1;
                            close_conn(conn);
                            break;
                        }
                        if (cont) continue;
                        free(conn->buf);
                        conn->buf = NULL;
                        conn->sent_len = 0;
                        conn->sent = 0;
                        conn->state = READING;
                        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &(struct epoll_event){
                            .events = EPOLLIN,
                            .data.ptr = conn
                        });
                        conn->req_len = 0;
                        memset(conn->req, '\0', sizeof(conn->req));
                    }
                    //pthread_mutex_lock(&lock);
                    //handle(events[i].data.ptr);
                    //pthread_mutex_unlock(&lock);
                }
            }
        }
    }
    pthread_mutex_destroy(&lock);
    close(server_fd);
    close(epoll_fd);
    for (int i = 0; i < ips; i++) {
        free(ip_entries[i]->ip);
    }
    free(ip_entries);
    SSL_CTX_free(ctx);
    return 0;
}
