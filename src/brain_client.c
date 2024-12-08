/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef WITH_BRAIN

#include "common.h"
#include "types.h"
#include "brain.h"
#include "brain_client.h"
#include "brain_utils.h"

bool brain_client_connect (hc_device_param_t *device_param, const status_ctx_t *status_ctx, const char *host, const int port, const char *password, u32 brain_session, u32 brain_attack, i64 passwords_max, u64 *highest)
{
  device_param->brain_link_client_fd   = 0;
  device_param->brain_link_recv_bytes  = 0;
  device_param->brain_link_send_bytes  = 0;
  device_param->brain_link_recv_active = false;
  device_param->brain_link_send_active = false;

  memset (&device_param->brain_link_recv_speed, 0, sizeof (link_speed_t));
  memset (&device_param->brain_link_send_speed, 0, sizeof (link_speed_t));

  const int brain_link_client_fd = socket (AF_INET, SOCK_STREAM, 0);

  if (brain_link_client_fd == -1)
  {
    brain_logging (stderr, 0, "socket: %s\n", strerror (errno));
    return false;
  }

  #if defined (__linux__)
  const int one = 1;

  if (setsockopt (brain_link_client_fd, SOL_TCP, TCP_NODELAY, &one, sizeof (one)) == -1)
  {
    brain_logging (stderr, 0, "setsockopt: %s\n", strerror (errno));
    close (brain_link_client_fd);
    return false;
  }
  #endif

  struct addrinfo hints;
  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  char port_str[8];
  memset (port_str, 0, sizeof (port_str));
  snprintf (port_str, sizeof (port_str), "%i", port);

  const char *host_real = (host == NULL) ? "127.0.0.1" : host;
  bool connected = false;
  struct addrinfo *address_info;

  const int rc_getaddrinfo = getaddrinfo (host_real, port_str, &hints, &address_info);

  if (rc_getaddrinfo == 0)
  {
    struct addrinfo *address_info_ptr;

    for (address_info_ptr = address_info; address_info_ptr != NULL; address_info_ptr = address_info_ptr->ai_next)
    {
      if (brain_connect (brain_link_client_fd, address_info_ptr->ai_addr, address_info_ptr->ai_addrlen, BRAIN_CLIENT_CONNECT_TIMEOUT) == 0)
      {
        connected = true;
        break;
      }
    }

    freeaddrinfo (address_info);
  }
  else
  {
    brain_logging (stderr, 0, "%s: %s\n", host_real, gai_strerror (rc_getaddrinfo));
    close (brain_link_client_fd);
    return false;
  }

  if (connected == false)
  {
    close (brain_link_client_fd);
    return false;
  }

  device_param->brain_link_client_fd = brain_link_client_fd;

  u32 brain_link_version = BRAIN_LINK_VERSION_CUR;

  if (brain_send (brain_link_client_fd, &brain_link_version, sizeof (brain_link_version), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, 0, "brain_send: %s\n", strerror (errno));
    close (brain_link_client_fd);
    return false;
  }

  u32 brain_link_version_ok = 0;

  if (brain_recv (brain_link_client_fd, &brain_link_version_ok, sizeof (brain_link_version_ok), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, 0, "brain_recv: %s\n", strerror (errno));
    close (brain_link_client_fd);
    return false;
  }

  if (brain_link_version_ok == 0)
  {
    brain_logging (stderr, 0, "Invalid brain server version\n");
    close (brain_link_client_fd);
    return false;
  }

  u32 challenge = 0;

  if (brain_recv (brain_link_client_fd, &challenge, sizeof (challenge), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, 0, "brain_recv: %s\n", strerror (errno));
    close (brain_link_client_fd);
    return false;
  }

  u64 response = brain_auth_hash (challenge, password, strlen (password));

  if (brain_send (brain_link_client_fd, &response, sizeof (response), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, 0, "brain_send: %s\n", strerror (errno));
    close (brain_link_client_fd);
    return false;
  }

  u32 password_ok = 0;

  if (brain_recv (brain_link_client_fd, &password_ok, sizeof (password_ok), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, 0, "brain_recv: %s\n", strerror (errno));
    close (brain_link_client_fd);
    return false;
  }

  if (password_ok == 0)
  {
    brain_logging (stderr, 0, "Invalid brain server password\n");
    close (brain_link_client_fd);
    return false;
  }

  if (brain_send (brain_link_client_fd, &brain_session, sizeof (brain_session), SEND_FLAGS, device_param, status_ctx) == false)
  {
    brain_logging (stderr, 0, "brain_send: %s\n", strerror (errno));
    close (brain_link_client_fd);
    return false;
  }

  if (brain_send (brain_link_client_fd, &brain_attack, sizeof (brain_attack), SEND_FLAGS, device_param, status_ctx) == false)
  {
    brain_logging (stderr, 0, "brain_send: %s\n", strerror (errno));
    close (brain_link_client_fd);
    return false;
  }

  if (brain_send (brain_link_client_fd, &passwords_max, sizeof (passwords_max), SEND_FLAGS, device_param, status_ctx) == false)
  {
    brain_logging (stderr, 0, "brain_send: %s\n", strerror (errno));
    close (brain_link_client_fd);
    return false;
  }

  if (brain_recv (brain_link_client_fd, highest, sizeof (u64), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, 0, "brain_recv: %s\n", strerror (errno));
    close (brain_link_client_fd);
    return false;
  }

  return true;
}

void brain_client_disconnect (hc_device_param_t *device_param)
{
  if (device_param->brain_link_client_fd > 2)
  {
    close (device_param->brain_link_client_fd);
  }

  device_param->brain_link_client_fd = -1;
}

bool brain_client_reserve (hc_device_param_t *device_param, const status_ctx_t *status_ctx, u64 words_off, u64 work, u64 *overlap)
{
  const int brain_link_client_fd = device_param->brain_link_client_fd;

  if (brain_link_client_fd == -1) return false;

  u8 operation = BRAIN_OPERATION_ATTACK_RESERVE;

  if (brain_send (brain_link_client_fd, &operation, sizeof (operation), SEND_FLAGS, device_param, status_ctx) == false) return false;
  if (brain_send (brain_link_client_fd, &words_off, sizeof (words_off), 0, device_param, status_ctx) == false) return false;
  if (brain_send (brain_link_client_fd, &work, sizeof (work), 0, device_param, status_ctx) == false) return false;

  if (brain_recv (brain_link_client_fd, overlap, sizeof (u64), 0, device_param, status_ctx) == false) return false;

  return true;
}

bool brain_client_commit (hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  if (device_param->pws_cnt == 0) return true;

  const int brain_link_client_fd = device_param->brain_link_client_fd;

  if (brain_link_client_fd == -1) return false;

  u8 operation = BRAIN_OPERATION_COMMIT;

  if (brain_send (brain_link_client_fd, &operation, sizeof (operation), SEND_FLAGS, device_param, status_ctx) == false) return false;

  return true;
}

bool brain_client_lookup (hc_device_param_t *device_param, const status_ctx_t *status_ctx)
{
  if (device_param->pws_pre_cnt == 0) return true;

  const int brain_link_client_fd = device_param->brain_link_client_fd;

  if (brain_link_client_fd == -1) return false;

  char *recvbuf = (char *) device_param->brain_link_in_buf;
  char *sendbuf = (char *) device_param->brain_link_out_buf;

  int in_size  = 0;
  int out_size = device_param->pws_pre_cnt * BRAIN_HASH_SIZE;

  u8 operation = BRAIN_OPERATION_HASH_LOOKUP;

  if (brain_send (brain_link_client_fd, &operation, sizeof (operation), SEND_FLAGS, device_param, status_ctx) == false) return false;
  if (brain_send (brain_link_client_fd, &out_size, sizeof (out_size), SEND_FLAGS, device_param, status_ctx) == false) return false;
  if (brain_send (brain_link_client_fd, sendbuf, out_size, SEND_FLAGS, device_param, status_ctx) == false) return false;

  if (brain_recv (brain_link_client_fd, &in_size, sizeof (in_size), 0, device_param, status_ctx) == false) return false;

  if (in_size > (int) device_param->size_brain_link_in) return false;

  if (brain_recv (brain_link_client_fd, recvbuf, (size_t) in_size, 0, device_param, status_ctx) == false) return false;

  return true;
}

void brain_client_generate_hash (u64 *hash, const char *line_buf, const size_t line_len)
{
  const u64 seed = 0;
  hash[0] = XXH64 (line_buf, line_len, seed);
}
#endif // WITH_BRAIN
