// 1. New header file: brain_bloom.h
#ifndef _BRAIN_BLOOM_H
#define _BRAIN_BLOOM_H

#include "types.h"
#include "common.h"

// Bloom filter configuration
#define BLOOM_FILTER_SIZE (1024 * 1024 * 8)  // 8MB in bits
#define BLOOM_HASH_FUNCTIONS 4

typedef struct {
    u8* bitarray;
    size_t size_in_bits;
    int num_hash_functions;
} brain_bloom_t;

// Bloom filter operations
bool brain_bloom_init(brain_bloom_t* bloom);
void brain_bloom_free(brain_bloom_t* bloom);
void brain_bloom_add(brain_bloom_t* bloom, const u32* hash);
bool brain_bloom_check(brain_bloom_t* bloom, const u32* hash);
void brain_bloom_clear(brain_bloom_t* bloom);

#endif // _BRAIN_BLOOM_H

// 2. Implementation file: brain_bloom.c
#include "brain_bloom.h"
#include "memory.h"
#include "shared.h"

// MurmurHash3 implementation for multiple hash functions
static u32 murmur3_32(const u32* key, u32 seed) {
    u32 h = seed;

    const u32 c1 = 0xcc9e2d51;
    const u32 c2 = 0x1b873593;

    // Body
    u32 k1 = *key;

    k1 *= c1;
    k1 = ROTL32(k1, 15);
    k1 *= c2;

    h ^= k1;
    h = ROTL32(h, 13);
    h = h * 5 + 0xe6546b64;

    // Finalization
    h ^= 4;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    return h;
}

bool brain_bloom_init(brain_bloom_t* bloom) {
    bloom->size_in_bits = BLOOM_FILTER_SIZE;
    bloom->num_hash_functions = BLOOM_HASH_FUNCTIONS;

    // Allocate bit array
    const size_t size_in_bytes = (bloom->size_in_bits + 7) / 8;
    bloom->bitarray = (u8*)hccalloc(size_in_bytes, sizeof(u8));

    return (bloom->bitarray != NULL);
}

void brain_bloom_free(brain_bloom_t* bloom) {
    if (bloom->bitarray) {
        hcfree(bloom->bitarray);
        bloom->bitarray = NULL;
    }
}

void brain_bloom_add(brain_bloom_t* bloom, const u32* hash) {
    for (int i = 0; i < bloom->num_hash_functions; i++) {
        u32 hash_value = murmur3_32(hash, i);
        size_t bit_pos = hash_value % bloom->size_in_bits;

        bloom->bitarray[bit_pos / 8] |= (1 << (bit_pos % 8));
    }
}

bool brain_bloom_check(brain_bloom_t* bloom, const u32* hash) {
    for (int i = 0; i < bloom->num_hash_functions; i++) {
        u32 hash_value = murmur3_32(hash, i);
        size_t bit_pos = hash_value % bloom->size_in_bits;

        if (!(bloom->bitarray[bit_pos / 8] & (1 << (bit_pos % 8)))) {
            return false; // Definitely not in set
        }
    }
    return true; // Probably in set
}

void brain_bloom_clear(brain_bloom_t* bloom) {
    const size_t size_in_bytes = (bloom->size_in_bits + 7) / 8;
    memset(bloom->bitarray, 0, size_in_bytes);
}

// 3. Modifications for brain_server.h
// Add to brain_server_db_hash_t structure:
struct brain_server_db_hash_t {
    // ... existing fields ...
    brain_bloom_t bloom;           // Bloom filter for quick rejection
    bool bloom_initialized;        // Track if Bloom filter is ready
};

// 4. Modifications for brain_server.c:

// In brain_server_db_hash_init():
void brain_server_db_hash_init(brain_server_db_hash_t *brain_server_db_hash, const u32 brain_session) {
    // ... existing initialization ...

    brain_server_db_hash->bloom_initialized = false;
    if (brain_bloom_init(&brain_server_db_hash->bloom)) {
        brain_server_db_hash->bloom_initialized = true;
    }
}

// In brain_server_db_hash_free():
void brain_server_db_hash_free(brain_server_db_hash_t *brain_server_db_hash) {
    // ... existing cleanup ...

    if (brain_server_db_hash->bloom_initialized) {
        brain_bloom_free(&brain_server_db_hash->bloom);
        brain_server_db_hash->bloom_initialized = false;
    }
}

// Modify the hash lookup sequence in brain_server_handle_client():
// In the BRAIN_OPERATION_HASH_LOOKUP section:
if (temp_cnt > 0) {
    i64 temp_idx_new = 0;

    for (i64 temp_idx = 0; temp_idx < temp_cnt; temp_idx++) {
        brain_server_hash_unique_t *cur = &temp_buf[temp_idx];

        // First check Bloom filter
        if (brain_server_db_hash->bloom_initialized &&
            !brain_bloom_check(&brain_server_db_hash->bloom, cur->hash)) {
            continue; // Definitely not in set, skip binary search
        }

        // Existing binary search as fallback
        const i64 r = brain_server_find_hash_long(cur->hash,
                                                brain_server_db_hash->long_buf,
                                                brain_server_db_hash->long_cnt);

        if (r != -1) {
            send_buf[cur->hash_idx] = 1;
        } else {
            brain_server_hash_unique_t *save = temp_buf + temp_idx_new;
            temp_idx_new++;
            save->hash[0] = cur->hash[0];
            save->hash[1] = cur->hash[1];
            save->hash_idx = cur->hash_idx;
        }
    }

    temp_cnt = temp_idx_new;
}

// Update the Bloom filter when adding new hashes:
// In the commit operation handler:
if (brain_server_db_hash->bloom_initialized) {
    for (i64 idx = 0; idx < temp_cnt; idx++) {
        brain_bloom_add(&brain_server_db_hash->bloom, temp_buf[idx].hash);
    }
}
