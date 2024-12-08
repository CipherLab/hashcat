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
#include "thread.h"

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
  #if defined (_WIN)

  if (timeout == 99999999)
  {
    // timeout not support on windows
  }

  if (connect (sockfd, addr, addrlen) == SOCKET_ERROR)
  {
    int err = WSAGetLastError ();

    char msg[256];

    memset (msg, 0, sizeof (msg));

    FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,   // flags
                   NULL,                // lpsource
                   err,                 // message id
                   MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),    // languageid
                   msg,                 // output buffer
                   sizeof (msg),        // size of msgbuf, bytes
                   NULL);               // va_list of arguments

    brain_logging (stderr, 0, "connect: %s\n", msg);

    return -1;
  }

  #else

  const int old_mode = fcntl (sockfd, F_GETFL, 0);

  if (fcntl (sockfd, F_SETFL, old_mode | O_NONBLOCK) == -1)
  {
    brain_logging (stderr, 0, "fcntl: %s\n", strerror (errno));

    return -1;
  }

  connect (sockfd, addr, addrlen);

  const int rc_select = select_write_timeout (sockfd, timeout);

  if (rc_select == -1) return -1;

  if (rc_select == 0)
  {
    brain_logging (stderr, 0, "connect: timeout\n");

    return -1;
  }

  int so_error = 0;

  socklen_t len = sizeof (so_error);

  if (getsockopt (sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) == -1)
  {
    brain_logging (stderr, 0, "getsockopt: %s\n", strerror (errno));

    return -1;
  }

  if (fcntl (sockfd, F_SETFL, old_mode) == -1)
  {
    brain_logging (stderr, 0, "fcntl: %s\n", strerror (errno));

    return -1;
  }

  if (so_error != 0)
  {
    brain_logging (stderr, 0, "connect: %s\n", strerror (so_error));

    return -1;
  }

  #endif

  return 0;
}

bool brain_send (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  char *ptr = (char *) buf;

  ssize_t s_pos;
  ssize_t s_len = len;

  for (s_pos = 0; s_pos < s_len - BRAIN_LINK_CHUNK_SIZE; s_pos += BRAIN_LINK_CHUNK_SIZE)
  {
    if (brain_send_all (sockfd, ptr + s_pos, BRAIN_LINK_CHUNK_SIZE, flags, device_param, status_ctx) == false) return false;

    if (status_ctx) if (status_ctx->run_thread_level1 == false) return false;
  }

  if (brain_send_all (sockfd, ptr + s_pos, s_len - s_pos, flags, device_param, status_ctx) == false) return false;

  if (status_ctx) if (status_ctx->run_thread_level1 == false) return false;

  return true;
}

bool brain_recv (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  char *ptr = (char *) buf;

  ssize_t s_pos;
  ssize_t s_len = len;

  for (s_pos = 0; s_pos < s_len - BRAIN_LINK_CHUNK_SIZE; s_pos += BRAIN_LINK_CHUNK_SIZE)
  {
    if (brain_recv_all (sockfd, ptr + s_pos, BRAIN_LINK_CHUNK_SIZE, flags, device_param, status_ctx) == false) return false;

    if (status_ctx) if (status_ctx->run_thread_level1 == false) return false;
  }

  if (brain_recv_all (sockfd, ptr + s_pos, s_len - s_pos, flags, device_param, status_ctx) == false) return false;

  if (status_ctx) if (status_ctx->run_thread_level1 == false) return false;

  return true;
}


bool brain_send_all (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  link_speed_t *link_speed = &device_param->brain_link_send_speed;

  if (device_param)
  {
    device_param->brain_link_send_active = true;

    hc_timer_set (&link_speed->timer[link_speed->pos]);
  }

  ssize_t nsend = send (sockfd, buf, len, flags);

  if (device_param)
  {
    link_speed->bytes[link_speed->pos] = nsend;

    if (link_speed->pos++ == LINK_SPEED_COUNT) link_speed->pos = 0;

    device_param->brain_link_send_bytes += nsend;
  }

  if (nsend <= 0) return false;

  if (status_ctx && status_ctx->run_thread_level1 == false) return false;

  while (nsend < (ssize_t) len)
  {
    char *buf_new = (char *) buf;

    if (device_param)
    {
      hc_timer_set (&link_speed->timer[link_speed->pos]);
    }

    ssize_t nsend_new = send (sockfd, buf_new + nsend, len - nsend, flags);

    if (device_param)
    {
      link_speed->bytes[link_speed->pos] = nsend_new;

      if (link_speed->pos++ == LINK_SPEED_COUNT) link_speed->pos = 0;

      device_param->brain_link_send_bytes += nsend_new;
    }

    if (nsend_new <= 0) return false;

    if (status_ctx && status_ctx->run_thread_level1 == false) break;

    nsend += nsend_new;
  }

  if (device_param)
  {
    device_param->brain_link_send_active = false;
  }

  return true;
}

bool brain_recv_all (int sockfd, void *buf, size_t len, int flags, hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  link_speed_t *link_speed = &device_param->brain_link_recv_speed;

  if (device_param)
  {
    device_param->brain_link_recv_active = true;

    hc_timer_set (&link_speed->timer[link_speed->pos]);
  }

  ssize_t nrecv = recv (sockfd, buf, len, flags);

  if (device_param)
  {
    link_speed->bytes[link_speed->pos] = nrecv;

    if (link_speed->pos++ == LINK_SPEED_COUNT) link_speed->pos = 0;

    device_param->brain_link_recv_bytes += nrecv;
  }

  if (nrecv <= 0) return false;

  if (status_ctx && status_ctx->run_thread_level1 == false) return false;

  while (nrecv < (ssize_t) len)
  {
    char *buf_new = (char *) buf;

    if (device_param)
    {
      hc_timer_set (&link_speed->timer[link_speed->pos]);
    }

    ssize_t nrecv_new = recv (sockfd, buf_new + nrecv, len - nrecv, flags);

    if (device_param)
    {
      link_speed->bytes[link_speed->pos] = nrecv_new;

      if (link_speed->pos++ == LINK_SPEED_COUNT) link_speed->pos = 0;

      device_param->brain_link_recv_bytes += nrecv_new;
    }

    if (nrecv_new <= 0) return false;

    if (status_ctx && status_ctx->run_thread_level1 == false) break;

    nrecv += nrecv_new;
  }

  if (device_param)
  {
    device_param->brain_link_recv_active = false;
  }

  return true;
}

u32 brain_compute_session (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t       *hashes       = hashcat_ctx->hashes;
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->brain_session != 0) return user_options->brain_session;

  const u64 seed = (const u64) hashconfig->hash_mode;

  XXH64_state_t *state = XXH64_createState ();

  XXH64_reset (state, seed);

  if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE)
  {
    // digest

    u32  digests_cnt = hashes->digests_cnt;
    u32 *digests_buf = (u32 *) hashes->digests_buf;

    XXH64_update (state, digests_buf, digests_cnt * hashconfig->dgst_size);

    // salt

    u32     salts_cnt = hashes->salts_cnt;
    salt_t *salts_buf = hashes->salts_buf;

    for (u32 salts_idx = 0; salts_idx < salts_cnt; salts_idx++)
    {
      salt_t *salt = salts_buf + salts_idx;

      XXH64_update (state, &salt->salt_iter, sizeof (salt->salt_iter));
      XXH64_update (state,  salt->salt_buf,  sizeof (salt->salt_buf));
    }

    // esalt

    if (hashconfig->esalt_size > 0)
    {
      void *esalts_buf = hashes->esalts_buf;

      XXH64_update (state, esalts_buf, digests_cnt * hashconfig->esalt_size);
    }
  }
  else
  {
    // using hash_encode is an easy workaround for dealing with optimizations
    // like OPTI_TYPE_PRECOMPUTE_MERKLE which cause different hashes in digests_buf
    // in case -O is used

    string_sized_t *string_sized_buf = (string_sized_t *) hccalloc (hashes->digests_cnt, sizeof (string_sized_t));

    int string_sized_cnt = 0;

    u8 *out_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

    u32 salts_cnt = hashes->salts_cnt;

    for (u32 salts_idx = 0; salts_idx < salts_cnt; salts_idx++)
    {
      salt_t *salt_buf = &hashes->salts_buf[salts_idx];

      for (u32 digest_idx = 0; digest_idx < salt_buf->digests_cnt; digest_idx++)
      {
        const int out_len = hash_encode (hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, (char *) out_buf, HCBUFSIZ_LARGE, salts_idx, digest_idx);

        string_sized_buf[string_sized_cnt].buf = (char *) hcmalloc (out_len + 1);
        string_sized_buf[string_sized_cnt].len = out_len;

        memcpy (string_sized_buf[string_sized_cnt].buf, out_buf, out_len);

        string_sized_cnt++;
      }
    }

    hcfree (out_buf);

    qsort (string_sized_buf, string_sized_cnt, sizeof (string_sized_t), sort_by_string_sized);

    for (int i = 0; i < string_sized_cnt; i++)
    {
      XXH64_update (state, string_sized_buf[i].buf, string_sized_buf[i].len);

      hcfree (string_sized_buf[i].buf);
    }

    hcfree (string_sized_buf);
  }

  const u32 session = (const u32) XXH64_digest (state);

  XXH64_freeState (state);

  return session;
}

u32 brain_compute_attack (hashcat_ctx_t *hashcat_ctx)
{
  const combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;
  const hashconfig_t     *hashconfig     = hashcat_ctx->hashconfig;
  const mask_ctx_t       *mask_ctx       = hashcat_ctx->mask_ctx;
  const straight_ctx_t   *straight_ctx   = hashcat_ctx->straight_ctx;
  const user_options_t   *user_options   = hashcat_ctx->user_options;

  XXH64_state_t *state = XXH64_createState ();

  XXH64_reset (state, user_options->brain_session);

  const int hash_mode   = hashconfig->hash_mode;
  const int attack_mode = user_options->attack_mode;

  XXH64_update (state, &hash_mode,   sizeof (hash_mode));
  XXH64_update (state, &attack_mode, sizeof (attack_mode));

  const int skip  = user_options->skip;
  const int limit = user_options->limit;

  XXH64_update (state, &skip,  sizeof (skip));
  XXH64_update (state, &limit, sizeof (limit));

  const int hex_salt = user_options->hex_salt;

  XXH64_update (state, &hex_salt, sizeof (hex_salt));

  const u32 opti_type = hashconfig->opti_type;

  XXH64_update (state, &opti_type, sizeof (opti_type));

  const u64 opts_type = hashconfig->opts_type;

  XXH64_update (state, &opts_type, sizeof (opts_type));

  const int hccapx_message_pair = user_options->hccapx_message_pair;

  XXH64_update (state, &hccapx_message_pair, sizeof (hccapx_message_pair));

  const int nonce_error_corrections = user_options->nonce_error_corrections;

  XXH64_update (state, &nonce_error_corrections, sizeof (nonce_error_corrections));

  const int veracrypt_pim_start = user_options->veracrypt_pim_start;

  XXH64_update (state, &veracrypt_pim_start, sizeof (veracrypt_pim_start));

  const int veracrypt_pim_stop = user_options->veracrypt_pim_stop;

  XXH64_update (state, &veracrypt_pim_stop, sizeof (veracrypt_pim_stop));

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    if (straight_ctx->dict)
    {
      const u64 wordlist_hash = brain_compute_attack_wordlist (straight_ctx->dict);

      XXH64_update (state, &wordlist_hash, sizeof (wordlist_hash));
    }

    const int hex_wordlist = user_options->hex_wordlist;

    XXH64_update (state, &hex_wordlist, sizeof (hex_wordlist));

    const int wordlist_autohex = user_options->wordlist_autohex;

    XXH64_update (state, &wordlist_autohex, sizeof (wordlist_autohex));

    if (user_options->encoding_from)
    {
      const char *encoding_from = user_options->encoding_from;

      XXH64_update (state, encoding_from, strlen (encoding_from));
    }

    if (user_options->encoding_to)
    {
      const char *encoding_to = user_options->encoding_to;

      XXH64_update (state, encoding_to, strlen (encoding_to));
    }

    if (user_options->rule_buf_l)
    {
      const char *rule_buf_l = user_options->rule_buf_l;

      XXH64_update (state, rule_buf_l, strlen (rule_buf_l));
    }

    if (user_options->rule_buf_r)
    {
      const char *rule_buf_r = user_options->rule_buf_r;

      XXH64_update (state, rule_buf_r, strlen (rule_buf_r));
    }

    const int loopback = user_options->loopback;

    XXH64_update (state, &loopback, sizeof (loopback));

    XXH64_update (state, straight_ctx->kernel_rules_buf, straight_ctx->kernel_rules_cnt * sizeof (kernel_rule_t));
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    const u64 wordlist1_hash = brain_compute_attack_wordlist (combinator_ctx->dict1);
    const u64 wordlist2_hash = brain_compute_attack_wordlist (combinator_ctx->dict2);

    XXH64_update (state, &wordlist1_hash, sizeof (wordlist1_hash));
    XXH64_update (state, &wordlist2_hash, sizeof (wordlist2_hash));

    const int hex_wordlist = user_options->hex_wordlist;

    XXH64_update (state, &hex_wordlist, sizeof (hex_wordlist));

    const int wordlist_autohex = user_options->wordlist_autohex;

    XXH64_update (state, &wordlist_autohex, sizeof (wordlist_autohex));

    if (user_options->encoding_from)
    {
      const char *encoding_from = user_options->encoding_from;

      XXH64_update (state, encoding_from, strlen (encoding_from));
    }

    if (user_options->encoding_to)
    {
      const char *encoding_to = user_options->encoding_to;

      XXH64_update (state, encoding_to, strlen (encoding_to));
    }

    if (user_options->rule_buf_l)
    {
      const char *rule_buf_l = user_options->rule_buf_l;

      XXH64_update (state, rule_buf_l, strlen (rule_buf_l));
    }

    if (user_options->rule_buf_r)
    {
      const char *rule_buf_r = user_options->rule_buf_r;

      XXH64_update (state, rule_buf_r, strlen (rule_buf_r));
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    const char *mask = mask_ctx->mask;

    XXH64_update (state, mask, strlen (mask));

    const int hex_charset = user_options->hex_charset;

    XXH64_update (state, &hex_charset, sizeof (hex_charset));

    const int markov_classic   = user_options->markov_classic;
    const int markov           = user_options->markov;
    const int markov_inverse   = user_options->markov_inverse;
    const int markov_threshold = user_options->markov_threshold;

    XXH64_update (state, &markov_classic,   sizeof (markov_classic));
    XXH64_update (state, &markov,           sizeof (markov));
    XXH64_update (state, &markov_inverse,   sizeof (markov_inverse));
    XXH64_update (state, &markov_threshold, sizeof (markov_threshold));

    if (user_options->markov_hcstat2)
    {
      const char *markov_hcstat2 = filename_from_filepath (user_options->markov_hcstat2);

      XXH64_update (state, markov_hcstat2, strlen (markov_hcstat2));
    }

    if (user_options->custom_charset_1)
    {
      const char *custom_charset_1 = user_options->custom_charset_1;

      XXH64_update (state, custom_charset_1, strlen (custom_charset_1));
    }

    if (user_options->custom_charset_2)
    {
      const char *custom_charset_2 = user_options->custom_charset_2;

      XXH64_update (state, custom_charset_2, strlen (custom_charset_2));
    }

    if (user_options->custom_charset_3)
    {
      const char *custom_charset_3 = user_options->custom_charset_3;

      XXH64_update (state, custom_charset_3, strlen (custom_charset_3));
    }

    if (user_options->custom_charset_4)
    {
      const char *custom_charset_4 = user_options->custom_charset_4;

      XXH64_update (state, custom_charset_4, strlen (custom_charset_4));
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    const u64 wordlist_hash = brain_compute_attack_wordlist (straight_ctx->dict);

    XXH64_update (state, &wordlist_hash, sizeof (wordlist_hash));

    const char *mask = mask_ctx->mask;

    XXH64_update (state, mask, strlen (mask));

    const int hex_charset = user_options->hex_charset;

    XXH64_update (state, &hex_charset, sizeof (hex_charset));

    const int markov_classic   = user_options->markov_classic;
    const int markov           = user_options->markov;
    const int markov_inverse   = user_options->markov_inverse;
    const int markov_threshold = user_options->markov_threshold;

    XXH64_update (state, &markov_classic,   sizeof (markov_classic));
    XXH64_update (state, &markov,           sizeof (markov));
    XXH64_update (state, &markov_inverse,   sizeof (markov_inverse));
    XXH64_update (state, &markov_threshold, sizeof (markov_threshold));

    if (user_options->markov_hcstat2)
    {
      const char *markov_hcstat2 = filename_from_filepath (user_options->markov_hcstat2);

      XXH64_update (state, markov_hcstat2, strlen (markov_hcstat2));
    }

    if (user_options->custom_charset_1)
    {
      const char *custom_charset_1 = user_options->custom_charset_1;

      XXH64_update (state, custom_charset_1, strlen (custom_charset_1));
    }

    if (user_options->custom_charset_2)
    {
      const char *custom_charset_2 = user_options->custom_charset_2;

      XXH64_update (state, custom_charset_2, strlen (custom_charset_2));
    }

    if (user_options->custom_charset_3)
    {
      const char *custom_charset_3 = user_options->custom_charset_3;

      XXH64_update (state, custom_charset_3, strlen (custom_charset_3));
    }

    if (user_options->custom_charset_4)
    {
      const char *custom_charset_4 = user_options->custom_charset_4;

      XXH64_update (state, custom_charset_4, strlen (custom_charset_4));
    }

    const int hex_wordlist = user_options->hex_wordlist;

    XXH64_update (state, &hex_wordlist, sizeof (hex_wordlist));

    const int wordlist_autohex = user_options->wordlist_autohex;

    XXH64_update (state, &wordlist_autohex, sizeof (wordlist_autohex));

    if (user_options->encoding_from)
    {
      const char *encoding_from = user_options->encoding_from;

      XXH64_update (state, encoding_from, strlen (encoding_from));
    }

    if (user_options->encoding_to)
    {
      const char *encoding_to = user_options->encoding_to;

      XXH64_update (state, encoding_to, strlen (encoding_to));
    }

    if (user_options->rule_buf_l)
    {
      const char *rule_buf_l = user_options->rule_buf_l;

      XXH64_update (state, rule_buf_l, strlen (rule_buf_l));
    }

    if (user_options->rule_buf_r)
    {
      const char *rule_buf_r = user_options->rule_buf_r;

      XXH64_update (state, rule_buf_r, strlen (rule_buf_r));
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    const char *mask = mask_ctx->mask;

    XXH64_update (state, mask, strlen (mask));

    const u64 wordlist_hash = brain_compute_attack_wordlist (straight_ctx->dict);

    XXH64_update (state, &wordlist_hash, sizeof (wordlist_hash));

    const int hex_charset = user_options->hex_charset;

    XXH64_update (state, &hex_charset, sizeof (hex_charset));

    const int markov_classic   = user_options->markov_classic;
    const int markov           = user_options->markov;
    const int markov_inverse   = user_options->markov_inverse;
    const int markov_threshold = user_options->markov_threshold;

    XXH64_update (state, &markov_classic,   sizeof (markov_classic));
    XXH64_update (state, &markov,           sizeof (markov));
    XXH64_update (state, &markov_inverse,   sizeof (markov_inverse));
    XXH64_update (state, &markov_threshold, sizeof (markov_threshold));

    if (user_options->markov_hcstat2)
    {
      const char *markov_hcstat2 = filename_from_filepath (user_options->markov_hcstat2);

      XXH64_update (state, markov_hcstat2, strlen (markov_hcstat2));
    }

    if (user_options->custom_charset_1)
    {
      const char *custom_charset_1 = user_options->custom_charset_1;

      XXH64_update (state, custom_charset_1, strlen (custom_charset_1));
    }

    if (user_options->custom_charset_2)
    {
      const char *custom_charset_2 = user_options->custom_charset_2;

      XXH64_update (state, custom_charset_2, strlen (custom_charset_2));
    }

    if (user_options->custom_charset_3)
    {
      const char *custom_charset_3 = user_options->custom_charset_3;

      XXH64_update (state, custom_charset_3, strlen (custom_charset_3));
    }

    if (user_options->custom_charset_4)
    {
      const char *custom_charset_4 = user_options->custom_charset_4;

      XXH64_update (state, custom_charset_4, strlen (custom_charset_4));
    }

    const int hex_wordlist = user_options->hex_wordlist;

    XXH64_update (state, &hex_wordlist, sizeof (hex_wordlist));

    const int wordlist_autohex = user_options->wordlist_autohex;

    XXH64_update (state, &wordlist_autohex, sizeof (wordlist_autohex));

    if (user_options->encoding_from)
    {
      const char *encoding_from = user_options->encoding_from;

      XXH64_update (state, encoding_from, strlen (encoding_from));
    }

    if (user_options->encoding_to)
    {
      const char *encoding_to = user_options->encoding_to;

      XXH64_update (state, encoding_to, strlen (encoding_to));
    }

    if (user_options->rule_buf_l)
    {
      const char *rule_buf_l = user_options->rule_buf_l;

      XXH64_update (state, rule_buf_l, strlen (rule_buf_l));
    }

    if (user_options->rule_buf_r)
    {
      const char *rule_buf_r = user_options->rule_buf_r;

      XXH64_update (state, rule_buf_r, strlen (rule_buf_r));
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    if (straight_ctx->dict)
    {
      const u64 wordlist_hash = brain_compute_attack_wordlist (straight_ctx->dict);

      XXH64_update (state, &wordlist_hash, sizeof (wordlist_hash));
    }

    const int hex_wordlist = user_options->hex_wordlist;

    XXH64_update (state, &hex_wordlist, sizeof (hex_wordlist));

    const int wordlist_autohex = user_options->wordlist_autohex;

    XXH64_update (state, &wordlist_autohex, sizeof (wordlist_autohex));

    if (user_options->encoding_from)
    {
      const char *encoding_from = user_options->encoding_from;

      XXH64_update (state, encoding_from, strlen (encoding_from));
    }

    if (user_options->encoding_to)
    {
      const char *encoding_to = user_options->encoding_to;

      XXH64_update (state, encoding_to, strlen (encoding_to));
    }

    if (user_options->rule_buf_l)
    {
      const char *rule_buf_l = user_options->rule_buf_l;

      XXH64_update (state, rule_buf_l, strlen (rule_buf_l));
    }

    XXH64_update (state, straight_ctx->kernel_rules_buf, straight_ctx->kernel_rules_cnt * sizeof (kernel_rule_t));
  }

  const u32 brain_attack = (const u32) XXH64_digest (state);

  XXH64_freeState (state);

  return brain_attack;
}

u64 brain_compute_attack_wordlist (const char *filename)
{
  XXH64_state_t *state = XXH64_createState ();

  XXH64_reset (state, 0);

  #define FBUFSZ 8192

  char buf[FBUFSZ];

  HCFILE fp;

  hc_fopen (&fp, filename, "rb");

  while (!hc_feof (&fp))
  {
    memset (buf, 0, sizeof (buf));

    const size_t nread = hc_fread (buf, 1, FBUFSZ, &fp);

    XXH64_update (state, buf, nread);
  }

  hc_fclose (&fp);

  const u64 hash = XXH64_digest (state);

  XXH64_freeState (state);

  return hash;
}

