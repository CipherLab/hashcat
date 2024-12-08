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

// Configuration for bloom filter
#define BLOOM_FILTER_SIZE (1024 * 1024 * 8)  // 8MB of bits
#define BLOOM_FILTER_HASHES 7                 // Number of hash functions

// Extend brain_server_db_hash_t to include bloom filter
typedef struct brain_server_db_hash_extended_t
{
  brain_server_db_hash_t base;
  brain_bloom_filter_t bloom;
  bool bloom_initialized;
} brain_server_db_hash_extended_t;

static void ensure_bloom_initialized(brain_server_db_hash_extended_t *db)
{
  if (!db->bloom_initialized)
  {
    brain_bloom_init(&db->bloom, BLOOM_FILTER_SIZE, BLOOM_FILTER_HASHES);

    // Populate bloom filter with existing hashes
    for (i64 i = 0; i < db->base.long_cnt; i++)
    {
      brain_bloom_add(&db->bloom, db->base.long_buf[i].hash);
    }

    db->bloom_initialized = true;
  }
}

// Modified search implementations using bloom filter
i64 brain_server_find_hash_long(const u32 *search, const brain_server_hash_long_t *buf, const i64 cnt)
{
  brain_server_db_hash_extended_t *db = (brain_server_db_hash_extended_t *)buf;

  ensure_bloom_initialized(db);

  // Quick check with bloom filter
  if (!brain_bloom_check(&db->bloom, search))
  {
    return -1; // Definitely not present
  }

  // Possible match, do binary search to confirm
  i64 l = 0;
  i64 r = cnt - 1;

  while (l <= r)
  {
    const i64 m = (l + r) >> 1;

    const int rc = brain_server_sort_hash(search, buf[m].hash);

    if (rc == 0) return m;

    if (rc > 0)
    {
      l = m + 1;
    }
    else
    {
      r = m - 1;
    }
  }

  return -1; // Not found
}

i64 brain_server_find_hash_short(const u32 *search, const brain_server_hash_short_t *buf, const i64 cnt)
{
  // Short-term storage doesn't use bloom filter since it's temporary
  if (cnt == 0) return -1;

  i64 l = 0;
  i64 r = cnt - 1;

  while (l <= r)
  {
    const i64 m = (l + r) >> 1;

    const int rc = brain_server_sort_hash(search, buf[m].hash);

    if (rc == 0) return m;

    if (rc > 0)
    {
      l = m + 1;
    }
    else
    {
      r = m - 1;
    }
  }

  return -1;
}

// Modified initialization to setup bloom filter
void brain_server_db_hash_init_extended(brain_server_db_hash_extended_t *brain_server_db_hash, const u32 brain_session)
{
  brain_server_db_hash_init(&brain_server_db_hash->base, brain_session);
  brain_server_db_hash->bloom_initialized = false;
}

// Modified free to cleanup bloom filter
void brain_server_db_hash_free_extended(brain_server_db_hash_extended_t *brain_server_db_hash)
{
  if (brain_server_db_hash->bloom_initialized)
  {
    brain_bloom_free(&brain_server_db_hash->bloom);
  }
  brain_server_db_hash_free(&brain_server_db_hash->base);
}

// Helper function to update bloom filter when adding new hashes
void brain_server_db_hash_update_bloom(brain_server_db_hash_extended_t *db, const u32 *hash)
{
  ensure_bloom_initialized(db);
  brain_bloom_add(&db->bloom, hash);
}
