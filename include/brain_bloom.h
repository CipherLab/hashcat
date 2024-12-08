/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _BRAIN_BLOOM_H
#define _BRAIN_BLOOM_H

#include "types.h"
#include "brain_types.h"

void brain_bloom_init (brain_bloom_filter_t *bloom, size_t size, int num_hashes);
void brain_bloom_free (brain_bloom_filter_t *bloom);
uint64_t brain_bloom_hash (const uint32_t *hash, int index);
void brain_bloom_add (brain_bloom_filter_t *bloom, const uint32_t *hash);
bool brain_bloom_check (brain_bloom_filter_t *bloom, const uint32_t *hash);
bool brain_bloom_save (brain_bloom_filter_t *bloom, const char *filename);
bool brain_bloom_load (brain_bloom_filter_t *bloom, const char *filename);

#endif // _BRAIN_BLOOM_H
