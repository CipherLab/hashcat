/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_BRAIN_CLIENT_H
#define HC_BRAIN_CLIENT_H

#include "types.h"
#include "status.h"

bool brain_client_connect    (hc_device_param_t *device_param, const status_ctx_t *status_ctx, const char *host, const int port, const char *password, u32 brain_session, u32 brain_attack, i64 passwords_max, u64 *highest);
void brain_client_disconnect (hc_device_param_t *device_param);
bool brain_client_reserve    (hc_device_param_t *device_param, const status_ctx_t *status_ctx, u64 words_off, u64 work, u64 *overlap);
bool brain_client_commit     (hc_device_param_t *device_param, const status_ctx_t *status_ctx);
bool brain_client_lookup     (hc_device_param_t *device_param, const status_ctx_t *status_ctx);
void brain_client_generate_hash (u64 *hash, const char *line_buf, const size_t line_len);

#endif // HC_BRAIN_CLIENT_H