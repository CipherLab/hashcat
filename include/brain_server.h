/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_BRAIN_SERVER_H
#define HC_BRAIN_SERVER_H

#include "types.h"

int brain_server_db_get_client_idx (brain_server_dbs_t *brain_server_dbs);
void brain_server_handle_signal (int signo);

HC_API_CALL
void *brain_server_handle_client (void *p);

HC_API_CALL  
void *brain_server_handle_dumps (void *p);

int brain_server (const char *listen_host, const int listen_port, const char *brain_password, const char *brain_session_whitelist, const u32 brain_server_timer);
bool brain_server_read_hash_dumps (brain_server_dbs_t *brain_server_dbs, const char *path);
bool brain_server_write_hash_dumps (brain_server_dbs_t *brain_server_dbs, const char *path);
bool brain_server_read_hash_dump (brain_server_db_hash_t *brain_server_db_hash, const char *file);
bool brain_server_write_hash_dump (brain_server_db_hash_t *brain_server_db_hash, const char *file);
bool brain_server_read_attack_dumps (brain_server_dbs_t *brain_server_dbs, const char *path);
bool brain_server_write_attack_dumps (brain_server_dbs_t *brain_server_dbs, const char *path);
bool brain_server_read_attack_dump (brain_server_db_attack_t *brain_server_db_attack, const char *file);
bool brain_server_write_attack_dump (brain_server_db_attack_t *brain_server_db_attack, const char *file);

void brain_server_db_hash_init (brain_server_db_hash_t *brain_server_db_hash, const u32 brain_session);
bool brain_server_db_hash_realloc (brain_server_db_hash_t *brain_server_db_hash, const i64 new_long_cnt);
void brain_server_db_hash_free (brain_server_db_hash_t *brain_server_db_hash);
void brain_server_db_attack_init (brain_server_db_attack_t *brain_server_db_attack, const u32 brain_attack);
bool brain_server_db_attack_realloc (brain_server_db_attack_t *brain_server_db_attack, const i64 new_long_cnt, const i64 new_short_cnt);
void brain_server_db_attack_free (brain_server_db_attack_t *brain_server_db_attack);

u64 brain_server_highest_attack (const brain_server_db_attack_t *buf);
u64 brain_server_highest_attack_long (const brain_server_attack_long_t *buf, const i64 cnt, const u64 start);
u64 brain_server_highest_attack_short (const brain_server_attack_short_t *buf, const i64 cnt, const u64 start);
u64 brain_server_find_attack_long (const brain_server_attack_long_t *buf, const i64 cnt, const u64 offset, const u64 length);
u64 brain_server_find_attack_short (const brain_server_attack_short_t *buf, const i64 cnt, const u64 offset, const u64 length);
i64 brain_server_find_hash_long (const u32 *search, const brain_server_hash_long_t *buf, const i64 cnt);
i64 brain_server_find_hash_short (const u32 *search, const brain_server_hash_short_t *buf, const i64 cnt);

int brain_server_sort_db_hash (const void *v1, const void *v2);
int brain_server_sort_db_attack (const void *v1, const void *v2);
int brain_server_sort_attack_long (const void *v1, const void *v2);
int brain_server_sort_attack_short (const void *v1, const void *v2);
int brain_server_sort_hash (const void *v1, const void *v2);
int brain_server_sort_hash_long (const void *v1, const void *v2);
int brain_server_sort_hash_short (const void *v1, const void *v2);
int brain_server_sort_hash_unique (const void *v1, const void *v2);

#endif // HC_BRAIN_SERVER_H