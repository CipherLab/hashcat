/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "brain.h"
#include "brain_utils.h"
#include "status.h"
#include "xxhash.h"
#include "shared.h"
#include "memory.h"

#if defined (_WIN)
#include <windows.h>
#include <wincrypt.h>
#endif

hc_thread_mutex_t mux_display;
hc_timer_t timer_logging;

int brain_logging (FILE *stream, const int client_idx, const char *format, ...)
{
  const double ms = hc_timer_get (timer_logging);
  hc_timer_set (&timer_logging);

  hc_thread_mutex_lock (mux_display);

  struct timeval v;
  gettimeofday (&v, NULL);

  fprintf (stream, "%u.%06u | %6.2fs | %3d | ", (u32) v.tv_sec, (u32) v.tv_usec, ms / 1000, client_idx);

  va_list ap;
  va_start (ap, format);
  const int len = vfprintf (stream, format, ap);
  va_end (ap);

  hc_thread_mutex_unlock (mux_display);

  return len;
}

u32 brain_auth_challenge (void)
{
  srand (time (NULL));
  u32 val = rand ();

  #if defined (_WIN)
  HCRYPTPROV hCryptProv;

  if (CryptAcquireContext (&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0) == true)
  {
    if (CryptGenRandom (hCryptProv, sizeof (val), (BYTE *) &val) == true)
    {
      // all good
    }
    else
    {
      brain_logging (stderr, 0, "CryptGenRandom: %d\n", (int) GetLastError ());
      return val;
    }

    CryptReleaseContext (hCryptProv, 0);
  }
  else
  {
    brain_logging (stderr, 0, "CryptAcquireContext: %d\n", (int) GetLastError ());
    return val;
  }

  #else

  static const char *const urandom = "/dev/urandom";
  HCFILE fp;

  if (hc_fopen (&fp, urandom, "rb") == false)
  {
    brain_logging (stderr, 0, "%s: %s\n", urandom, strerror (errno));
    return val;
  }

  if (hc_fread (&val, sizeof (val), 1, &fp) != 1)
  {
    brain_logging (stderr, 0, "%s: %s\n", urandom, strerror (errno));
    hc_fclose (&fp);
    return val;
  }

  hc_fclose (&fp);
  #endif

  return val;
}

u64 brain_auth_hash (const u32 challenge, const char *pw_buf, const int pw_len)
{
  u64 response = XXH64 (pw_buf, pw_len, challenge);

  for (int i = 0; i < 100000; i++)
  {
    response = XXH64 (&response, 8, 0);
  }

  return response;
}

int brain_connect (int sockfd, const struct sockaddr *addr, socklen_t addrlen, const int timeout)
{
  struct timeval tv;

  tv.tv_sec  = timeout;
  tv.tv_usec = 0;

  setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof (tv));
  setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *) &tv, sizeof (tv));

  return connect (sockfd, addr, addrlen);
}

bool brain_recv (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  char *buf_ptr = (char *) buf;

  ssize_t remaining = len;

  while (remaining > 0)
  {
    if ((status_ctx != NULL) && (status_ctx->run_thread_level1 == false)) return false;

    ssize_t received = recv (sockfd, buf_ptr, (size_t) remaining, flags);

    if (received == -1) return false;
    if (received ==  0) return false;

    if (device_param != NULL)
    {
      device_param->brain_recv_bytes += (u64) received;
    }

    buf_ptr   += received;
    remaining -= received;
  }

  return true;
}

bool brain_send (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  char *buf_ptr = (char *) buf;

  ssize_t remaining = len;

  while (remaining > 0)
  {
    if ((status_ctx != NULL) && (status_ctx->run_thread_level1 == false)) return false;

    ssize_t sent = send (sockfd, buf_ptr, (size_t) remaining, flags);

    if (sent == -1) return false;
    if (sent ==  0) return false;

    if (device_param != NULL)
    {
      device_param->brain_send_bytes += (u64) sent;
    }

    buf_ptr   += sent;
    remaining -= sent;
  }

  return true;
}

bool brain_recv_all (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  return brain_recv (sockfd, buf, len, flags, device_param, status_ctx);
}

bool brain_send_all (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  return brain_send (sockfd, buf, len, flags, device_param, status_ctx);
}

u32 brain_compute_session (hashcat_ctx_t *hashcat_ctx)
{
  const folder_config_t *folder_config = hashcat_ctx->folder_config;
  const user_options_t  *user_options  = hashcat_ctx->user_options;
  const hashconfig_t    *hashconfig    = hashcat_ctx->hashconfig;

  XXH64_state_t* const state = XXH64_createState ();

  XXH64_reset  (state, 0);

  XXH64_update (state, &hashconfig->hash_mode, sizeof (u32));
  XXH64_update (state, user_options->rule_buf_l, strlen (user_options->rule_buf_l));
  XXH64_update (state, user_options->rule_buf_r, strlen (user_options->rule_buf_r));
  XXH64_update (state, folder_config->scratch_buf, strlen (folder_config->scratch_buf));

  const u64 hash = XXH64_digest (state);

  XXH64_freeState (state);

  return (u32) hash;
}

u32 brain_compute_attack (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t  *user_options  = hashcat_ctx->user_options;

  XXH64_state_t* const state = XXH64_createState ();

  XXH64_reset  (state, 0);

  for (int i = 0; i < user_options->markov_threshold; i++)
  {
    XXH64_update (state, &i, sizeof (int));
  }

  const u64 hash = XXH64_digest (state);

  XXH64_freeState (state);

  return (u32) hash;
}

u64 brain_compute_attack_wordlist (const char *filename)
{
  XXH64_state_t* const state = XXH64_createState ();

  XXH64_reset  (state, 0);

  XXH64_update (state, filename, strlen (filename));

  const u64 hash = XXH64_digest (state);

  XXH64_freeState (state);

  return hash;
}