/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_BRAIN_UTILS_H
#define HC_BRAIN_UTILS_H

#include <stdio.h>
#include "types.h"

int brain_logging (FILE *stream, const int client_idx, const char *format, ...);
u32 brain_auth_challenge (void);
u64 brain_auth_hash (const u32 challenge, const char *pw_buf, const int pw_len);
int brain_connect (int sockfd, const struct sockaddr *addr, socklen_t addrlen, const int timeout);
bool brain_recv (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx);
bool brain_send (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx);
bool brain_recv_all (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx);
bool brain_send_all (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx);
u32 brain_compute_session (hashcat_ctx_t *hashcat_ctx);
u32 brain_compute_attack (hashcat_ctx_t *hashcat_ctx);
u64 brain_compute_attack_wordlist (const char *filename);

extern hc_thread_mutex_t mux_display;
extern hc_timer_t timer_logging;

#endif // HC_BRAIN_UTILS_H