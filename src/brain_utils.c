/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "brain.h"

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

// ... [Rest of utility functions from brain.c]
