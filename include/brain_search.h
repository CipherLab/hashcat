/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "brain.h"


u64 brain_server_find_attack_long (const brain_server_attack_long_t *buf, const i64 cnt, const u64 offset, const u64 length);
u64 brain_server_find_attack_short (const brain_server_attack_short_t *buf, const i64 cnt, const u64 offset, const u64 length);
i64 brain_server_find_hash_long (const u32 *search, const brain_server_hash_long_t *buf, const i64 cnt);
i64 brain_server_find_hash_short (const u32 *search, const brain_server_hash_short_t *buf, const i64 cnt);


