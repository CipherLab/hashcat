/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "brain.h"
#include "brain_server.h"
#include "brain_utils.h"
#include "brain_bloom.h"
#include "thread.h"
#include "memory.h"
#include "shared.h"

i64 brain_server_find_hash_long(const u32 *search, const brain_server_hash_long_t *buf, const i64 cnt) {
    // Binary search implementation
    i64 l = 0;
    i64 r = cnt - 1;

    while (l <= r) {
        const i64 m = (l + r) >> 1;

        const brain_server_hash_long_t *long_entry = &buf[m];

        const int rc = brain_server_sort_hash(search, long_entry->hash);

        if (rc == 0) return m;
        if (rc > 0)  l = m + 1;
        if (rc < 0)  r = m - 1;
    }

    return -1;
}

i64 brain_server_find_hash_short(const u32 *search, const brain_server_hash_short_t *buf, const i64 cnt) {
    // Binary search implementation
    i64 l = 0;
    i64 r = cnt - 1;

    while (l <= r) {
        const i64 m = (l + r) >> 1;

        const brain_server_hash_short_t *short_entry = &buf[m];

        const int rc = brain_server_sort_hash(search, short_entry->hash);

        if (rc == 0) return m;
        if (rc > 0)  l = m + 1;
        if (rc < 0)  r = m - 1;
    }

    return -1;
}

u64 brain_server_find_attack_long(const brain_server_attack_long_t *buf, const i64 cnt, const u64 offset, const u64 length) {
    u64 overlap = 0;

    for (i64 idx = 0; idx < cnt; idx++) {
        const brain_server_attack_long_t *long_entry = &buf[idx];

        if ((offset >= long_entry->offset) && (offset < long_entry->offset + long_entry->length)) {
            const u64 overlapping = MIN(length, (long_entry->offset + long_entry->length) - offset);

            overlap += overlapping;

            if (overlap == length) break;
        }
    }

    return overlap;
}

u64 brain_server_find_attack_short(const brain_server_attack_short_t *buf, const i64 cnt, const u64 offset, const u64 length) {
    u64 overlap = 0;

    for (i64 idx = 0; idx < cnt; idx++) {
        const brain_server_attack_short_t *short_entry = &buf[idx];

        if ((offset >= short_entry->offset) && (offset < short_entry->offset + short_entry->length)) {
            const u64 overlapping = MIN(length, (short_entry->offset + short_entry->length) - offset);

            overlap += overlapping;

            if (overlap == length) break;
        }
    }

    return overlap;
}
