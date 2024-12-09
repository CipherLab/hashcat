/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "brain_bloom.h"
#include "memory.h"

bool brain_bloom_init(brain_bloom_filter_t *bloom, size_t size, int num_hashes) {
    if (bloom == NULL || size == 0 || num_hashes <= 0) {
        return false;
    }

    // Allocate memory for the bit array
    bloom->bits = (uint64_t*) hccalloc((size + 63) / 64, sizeof(uint64_t));

    if (bloom->bits == NULL) {
        return false;
    }

    bloom->size = size;
    bloom->num_hashes = num_hashes;

    return true;
}

void brain_bloom_free(brain_bloom_filter_t *bloom) {
    if (bloom && bloom->bits) {
        hcfree(bloom->bits);
        bloom->bits = NULL;
        bloom->size = 0;
        bloom->num_hashes = 0;
    }
}

uint64_t brain_bloom_hash(const uint32_t *hash, int index) {
    // Simple hash function using the hash value and index
    uint64_t h = hash[0] ^ (hash[1] << 16);
    h = h * (index + 1);
    return h;
}

void brain_bloom_add(brain_bloom_filter_t *bloom, const uint32_t *hash) {
    if (!bloom || !bloom->bits) return;

    for (int i = 0; i < bloom->num_hashes; i++) {
        uint64_t bit_pos = brain_bloom_hash(hash, i) % bloom->size;
        bloom->bits[bit_pos / 64] |= (1ULL << (bit_pos % 64));
    }
}

bool brain_bloom_check(brain_bloom_filter_t *bloom, const uint32_t *hash) {
    if (!bloom || !bloom->bits) return false;

    for (int i = 0; i < bloom->num_hashes; i++) {
        uint64_t bit_pos = brain_bloom_hash(hash, i) % bloom->size;
        if (!(bloom->bits[bit_pos / 64] & (1ULL << (bit_pos % 64)))) {
            return false;
        }
    }
    return true;
}

bool brain_bloom_save(brain_bloom_filter_t *bloom, const char *filename) {
    if (!bloom || !bloom->bits || !filename) {
        return false;
    }

    FILE *file = fopen(filename, "wb");
    if (!file) {
        return false;
    }

    // Write metadata
    if (fwrite(&bloom->size, sizeof(size_t), 1, file) != 1 ||
        fwrite(&bloom->num_hashes, sizeof(int), 1, file) != 1) {
        fclose(file);
        return false;
    }

    // Calculate number of uint64_t elements needed to represent the bits
    size_t bit_array_size = (bloom->size + 63) / 64;

    // Write bit array
    if (fwrite(bloom->bits, sizeof(uint64_t), bit_array_size, file) != bit_array_size) {
        fclose(file);
        return false;
    }

    fclose(file);
    return true;
}

bool brain_bloom_load(brain_bloom_filter_t *bloom, const char *filename) {
    if (!bloom || !filename) {
        return false;
    }

    FILE *file = fopen(filename, "rb");
    if (!file) {
        return false;
    }

    // Read metadata
    size_t size;
    int num_hashes;
    if (fread(&size, sizeof(size_t), 1, file) != 1 ||
        fread(&num_hashes, sizeof(int), 1, file) != 1) {
        fclose(file);
        return false;
    }

    // Free existing bits if any
    brain_bloom_free(bloom);

    // Initialize Bloom filter with loaded metadata
    if (!brain_bloom_init(bloom, size, num_hashes)) {
        fclose(file);
        return false;
    }

    // Calculate number of uint64_t elements needed to represent the bits
    size_t bit_array_size = (size + 63) / 64;

    // Read bit array
    if (fread(bloom->bits, sizeof(uint64_t), bit_array_size, file) != bit_array_size) {
        brain_bloom_free(bloom);
        fclose(file);
        return false;
    }

    fclose(file);
    return true;
}
