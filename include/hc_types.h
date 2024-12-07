/**
 * Common type definitions for hashcat
 */

#ifndef HC_TYPES_H
#define HC_TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

// Consistent type definitions
typedef unsigned char      u8;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef long long          i64;

// Placeholder structs for types referenced in headers
typedef struct {
    // Add necessary fields for folder configuration
} folder_config_t;

typedef struct {
    // Add necessary fields for hash configuration
} hashconfig_t;

typedef struct {
    // Add necessary fields for token
} hc_token_t;

typedef struct {
    FILE *file;
} HCFILE;

typedef struct {
    // Brain link speed tracking
    struct {
        double timer[16];
        ssize_t bytes[16];
        int pos;
    } brain_link_recv_speed;

    struct {
        double timer[16];
        ssize_t bytes[16];
        int pos;
    } brain_link_send_speed;

    int brain_link_client_fd;
    size_t brain_link_recv_bytes;
    size_t brain_link_send_bytes;
    bool brain_link_recv_active;
    bool brain_link_send_active;

    void *brain_link_in_buf;
    void *brain_link_out_buf;
    size_t size_brain_link_in;
    size_t pws_pre_cnt;
    size_t pws_cnt;
} hc_device_param_t;

typedef struct {
    bool run_thread_level1;
} status_ctx_t;

typedef struct {
    bool support;
    bool enabled;
} brain_ctx_t;

typedef struct {
    // Placeholder for hashcat context
    brain_ctx_t *brain_ctx;
    hashconfig_t *hashconfig;
    hc_device_param_t *device_param;
    void *user_options;
    void *hashes;
} hashcat_ctx_t;

// Utility functions
int sort_by_string_sized(const void *p1, const void *p2);

#endif // HC_TYPES_H
