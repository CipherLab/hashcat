/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _BRAIN_TYPES_H
#define _BRAIN_TYPES_H

#include <stddef.h>
#include <stdbool.h>
#include "xxhash.h"

#define BRAIN_HASH_SIZE 8      // Size in bytes of xxHash output used
#define BRAIN_BLOOM_SIZE 1024  // Size of bloom filter in bits
#define BRAIN_BLOOM_HASHES 4   // Number of hash functions to use

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

typedef struct {
  size_t size;       // Size of bit array in bits
  int num_hashes;    // Number of hash functions to use
  u8 *bits;         // Bit array for bloom filter
} brain_bloom_filter_t;

typedef struct {
  u32 brain_session;               // Session identifier
  i64 long_cnt;                    // Count of long-term entries
  i64 long_alloc;                  // Allocated size of long buffer
  brain_server_hash_long_t *long_buf;  // Long-term hash buffer
  bool write_hashes;               // Flag to write hashes to disk
  brain_bloom_filter_t bloom;      // Bloom filter for this session
  hc_thread_mutex_t *mux_hr;       // Read mutex
  hc_thread_mutex_t *mux_hg;       // Global mutex
  int hb;                          // Hash buffer counter
} brain_server_db_hash_t;

typedef struct {
  brain_server_db_hash_t *hash_buf;  // Array of hash databases
  brain_server_db_attack_t *attack_buf; // Array of attack databases  
  int *client_slots;                 // Array of client slot states
  i64 hash_cnt;                      // Count of hash databases
  i64 attack_cnt;                    // Count of attack databases
  hc_thread_mutex_t *mux_dbs;        // Database mutex
} brain_server_dbs_t;

#endif // _BRAIN_TYPES_H
