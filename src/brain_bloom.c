/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <stdio.h>
#include "brain_bloom.h"
#include "memory.h"

void brain_bloom_init (brain_bloom_filter_t *bloom, size_t size, int num_hashes)
{
  bloom->size = size;
  bloom->num_hashes = num_hashes;
  bloom->bits = (u8 *) hccalloc ((size + 7) / 8, sizeof(u8)); // Size in bytes rounded up
}

void brain_bloom_free (brain_bloom_filter_t *bloom)
{
  if (bloom->bits)
  {
    hcfree (bloom->bits);
    bloom->bits = NULL;
  }
}

u64 brain_bloom_hash (const u32 *hash, int index)
{
  return XXH64 (hash, BRAIN_HASH_SIZE, index * 31337);
}

void brain_bloom_add (brain_bloom_filter_t *bloom, const u32 *hash)
{
  for (int i = 0; i < bloom->num_hashes; i++)
  {
    u64 hash_val = brain_bloom_hash (hash, i) % bloom->size;
    bloom->bits[hash_val / 8] |= (1 << (hash_val % 8));
  }
}

bool brain_bloom_check (brain_bloom_filter_t *bloom, const u32 *hash)
{
  for (int i = 0; i < bloom->num_hashes; i++)
  {
    u64 hash_val = brain_bloom_hash (hash, i) % bloom->size;
    if (!(bloom->bits[hash_val / 8] & (1 << (hash_val % 8))))
    {
      return false; // Definitely not in set
    }
  }
  return true; // Possibly in set
}

bool brain_bloom_save (brain_bloom_filter_t *bloom, const char *filename)
{
  FILE *fp = fopen(filename, "wb");
  if (!fp) return false;

  // Write metadata
  if (fwrite(&bloom->size, sizeof(size_t), 1, fp) != 1) goto error;
  if (fwrite(&bloom->num_hashes, sizeof(int), 1, fp) != 1) goto error;

  // Write bit array
  size_t bytes = (bloom->size + 7) / 8;
  if (fwrite(bloom->bits, sizeof(u8), bytes, fp) != bytes) goto error;

  fclose(fp);
  return true;

error:
  fclose(fp);
  return false;
}

bool brain_bloom_load (brain_bloom_filter_t *bloom, const char *filename)
{
  FILE *fp = fopen(filename, "rb");
  if (!fp) return false;

  // Read metadata
  size_t size;
  int num_hashes;
  if (fread(&size, sizeof(size_t), 1, fp) != 1) goto error;
  if (fread(&num_hashes, sizeof(int), 1, fp) != 1) goto error;

  // Initialize bloom filter
  brain_bloom_init(bloom, size, num_hashes);

  // Read bit array
  size_t bytes = (size + 7) / 8;
  if (fread(bloom->bits, sizeof(u8), bytes, fp) != bytes) goto error;

  fclose(fp);
  return true;

error:
  fclose(fp);
  brain_bloom_free(bloom);
  return false;
}
