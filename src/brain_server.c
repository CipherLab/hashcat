/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */


#include "common.h"
#include "types.h"
#include "brain.h"
#include "brain_server.h"
#include "brain_utils.h"
#include "thread.h"
#include "memory.h"
#include "shared.h"
static bool keep_running = true;

HC_API_CALL void *brain_server_handle_client (void *p)
{
  brain_server_client_options_t *brain_server_client_options = (brain_server_client_options_t *) p;

  const int   client_idx            = brain_server_client_options->client_idx;
  const int   client_fd             = brain_server_client_options->client_fd;
  const char *auth_password         = brain_server_client_options->auth_password;
  const u32  *session_whitelist_buf = brain_server_client_options->session_whitelist_buf;
  const int   session_whitelist_cnt = brain_server_client_options->session_whitelist_cnt;

  brain_server_dbs_t *brain_server_dbs = brain_server_client_options->brain_server_dbs;

  // client configuration

  #if defined (__linux__)
  const int one = 1;

  if (setsockopt (client_fd, SOL_TCP, TCP_NODELAY, &one, sizeof (one)) == -1)
  {
    brain_logging (stderr, client_idx, "setsockopt: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }
  #else

  #endif

  u32 brain_link_version = 0;

  if (brain_recv (client_fd, &brain_link_version, sizeof (brain_link_version), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_recv: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  u32 brain_link_version_ok = (brain_link_version >= (u32) BRAIN_LINK_VERSION_MIN) ? 1 : 0;

  if (brain_send (client_fd, &brain_link_version_ok, sizeof (brain_link_version_ok), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_send: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  if (brain_link_version_ok == 0)
  {
    brain_logging (stderr, client_idx, "Invalid version\n");

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  u32 challenge = brain_auth_challenge ();

  if (brain_send (client_fd, &challenge, sizeof (challenge), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_send: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  u64 response = 0;

  if (brain_recv (client_fd, &response, sizeof (response), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_recv: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  u64 auth_hash = brain_auth_hash (challenge, auth_password, strlen (auth_password));

  u32 password_ok = (auth_hash == response) ? 1 : 0;

  if (brain_send (client_fd, &password_ok, sizeof (password_ok), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_send: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  if (password_ok == 0)
  {
    brain_logging (stderr, client_idx, "Invalid password\n");

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  u32 brain_session = 0;

  if (brain_recv (client_fd, &brain_session, sizeof (brain_session), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_recv: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  if (session_whitelist_cnt > 0)
  {
    bool found = false;

    for (int idx = 0; idx < session_whitelist_cnt; idx++)
    {
      if (session_whitelist_buf[idx] == brain_session)
      {
        found = true;

        break;
      }
    }

    if (found == false)
    {
      brain_logging (stderr, client_idx, "Invalid brain session: 0x%08x\n", brain_session);

      brain_server_dbs->client_slots[client_idx] = 0;

      close (client_fd);

      return NULL;
    }
  }

  u32 brain_attack = 0;

  if (brain_recv (client_fd, &brain_attack, sizeof (brain_attack), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_recv: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  i64 passwords_max = 0;

  if (brain_recv (client_fd, &passwords_max, sizeof (passwords_max), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_recv: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  if (passwords_max >= BRAIN_LINK_CANDIDATES_MAX)
  {
    brain_logging (stderr, client_idx, "Too large candidate allocation buffer size\n");

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  brain_logging (stdout, client_idx, "Session: 0x%08x, Attack: 0x%08x, Kernel-power: %" PRIu64 "\n", brain_session, brain_attack, passwords_max);

  // so far so good

  hc_thread_mutex_lock (brain_server_dbs->mux_dbs);

  // long term memory

  brain_server_db_hash_t key_hash;

  key_hash.brain_session = brain_session;

  #if defined (_WIN)
  unsigned int find_hash_cnt = (unsigned int) brain_server_dbs->hash_cnt;
  #else
  size_t find_hash_cnt = (size_t) brain_server_dbs->hash_cnt;
  #endif

  brain_server_db_hash_t *brain_server_db_hash = (brain_server_db_hash_t *) lfind (&key_hash, brain_server_dbs->hash_buf, &find_hash_cnt, sizeof (brain_server_db_hash_t), brain_server_sort_db_hash);

  if (brain_server_db_hash == NULL)
  {
    if (brain_server_dbs->hash_cnt >= BRAIN_SERVER_SESSIONS_MAX)
    {
      brain_logging (stderr, 0, "too many sessions\n");

      brain_server_dbs->client_slots[client_idx] = 0;

      hc_thread_mutex_unlock (brain_server_dbs->mux_dbs);

      close (client_fd);

      return NULL;
    }

    brain_server_db_hash = &brain_server_dbs->hash_buf[brain_server_dbs->hash_cnt];

    brain_server_db_hash_init (brain_server_db_hash, brain_session);

    brain_server_dbs->hash_cnt++;
  }

  // attack memory

  brain_server_db_attack_t key_attack;

  key_attack.brain_attack = brain_attack;

  #if defined (_WIN)
  unsigned int find_attack_cnt = (unsigned int) brain_server_dbs->attack_cnt;
  #else
  size_t find_attack_cnt = (size_t) brain_server_dbs->attack_cnt;
  #endif

  brain_server_db_attack_t *brain_server_db_attack = (brain_server_db_attack_t *) lfind (&key_attack, brain_server_dbs->attack_buf, &find_attack_cnt, sizeof (brain_server_db_attack_t), brain_server_sort_db_attack);

  if (brain_server_db_attack == NULL)
  {
    if (brain_server_dbs->attack_cnt >= BRAIN_SERVER_ATTACKS_MAX)
    {
      brain_logging (stderr, 0, "too many attacks\n");

      brain_server_dbs->client_slots[client_idx] = 0;

      hc_thread_mutex_unlock (brain_server_dbs->mux_dbs);

      close (client_fd);

      return NULL;
    }

    brain_server_db_attack = &brain_server_dbs->attack_buf[brain_server_dbs->attack_cnt];

    brain_server_db_attack_init (brain_server_db_attack, brain_attack);

    brain_server_dbs->attack_cnt++;
  }

  hc_thread_mutex_unlock (brain_server_dbs->mux_dbs);

  // highest position of that attack

  u64 highest = brain_server_highest_attack (brain_server_db_attack);

  if (brain_send (client_fd, &highest, sizeof (highest), 0, NULL, NULL) == false)
  {
    brain_logging (stderr, client_idx, "brain_send: %s\n", strerror (errno));

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  // recv

  const size_t recv_size = passwords_max * BRAIN_HASH_SIZE;

  u32 *recv_buf = (u32 *) hcmalloc (recv_size);

  if (recv_buf == NULL)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  // send

  const size_t send_size = passwords_max * sizeof (char);

  u8 *send_buf = (u8  *) hcmalloc (send_size); // we can reduce this to 1/8 if we use bits instead of bytes

  if (send_buf == NULL)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  // temp

  brain_server_hash_unique_t *temp_buf = (brain_server_hash_unique_t *) hccalloc (passwords_max, sizeof (brain_server_hash_unique_t));

  if (temp_buf == NULL)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  // short global alloc

  brain_server_db_short_t *brain_server_db_short = (brain_server_db_short_t *) hcmalloc (sizeof (brain_server_db_short_t));

  brain_server_db_short->short_cnt = 0;
  brain_server_db_short->short_buf = (brain_server_hash_short_t *) hccalloc (passwords_max, sizeof (brain_server_hash_short_t));

  if (brain_server_db_short->short_buf == NULL)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    brain_server_dbs->client_slots[client_idx] = 0;

    close (client_fd);

    return NULL;
  }

  // main loop

  while (keep_running == true)
  {
    // wait for client to send data, but not too long

    const int rc_select = select_read_timeout (client_fd, 1);

    if (rc_select == -1) break;

    if (rc_select == 0) continue;

    // there's data

    u8 operation = 0;

    if (brain_recv (client_fd, &operation, sizeof (operation), 0, NULL, NULL) == false) break;

    // U = update
    // R = request
    // C = commit


    if (operation == BRAIN_OPERATION_ATTACK_RESERVE)
    {
      u64 offset = 0;
      u64 length = 0;

      if (brain_recv (client_fd, &offset, sizeof (offset), 0, NULL, NULL) == false) break;
      if (brain_recv (client_fd, &length, sizeof (length), 0, NULL, NULL) == false) break;

      // time the lookups for debugging

      hc_timer_t timer_reserved;


      hc_thread_mutex_lock (brain_server_db_attack->mux_ag);

      u64 overlap = 0;

      overlap += brain_server_find_attack_short (brain_server_db_attack->short_buf, brain_server_db_attack->short_cnt, offset, length);
      overlap += brain_server_find_attack_long  (brain_server_db_attack->long_buf,  brain_server_db_attack->long_cnt,  offset + overlap, length - overlap);

      if (overlap < length)
      {
        if (brain_server_db_attack_realloc (brain_server_db_attack, 0, 1) == true)
        {
          brain_server_db_attack->short_buf[brain_server_db_attack->short_cnt].offset     = offset + overlap;
          brain_server_db_attack->short_buf[brain_server_db_attack->short_cnt].length     = length - overlap;
          brain_server_db_attack->short_buf[brain_server_db_attack->short_cnt].client_idx = client_idx;

          brain_server_db_attack->short_cnt++;

          qsort (brain_server_db_attack->short_buf, brain_server_db_attack->short_cnt, sizeof (brain_server_attack_short_t), brain_server_sort_attack_short);
        }
      }

      hc_thread_mutex_unlock (brain_server_db_attack->mux_ag);

      if (brain_send (client_fd, &overlap, sizeof (overlap), SEND_FLAGS, NULL, NULL) == false) break;

      const double ms = hc_timer_get (timer_reserved);

      brain_logging (stdout, client_idx, "R | %8.2f ms | Offset: %" PRIu64 ", Length: %" PRIu64 ", Overlap: %" PRIu64 "\n", ms, offset, length, overlap);
    }
    else if (operation == BRAIN_OPERATION_COMMIT)
    {
      // time the lookups for debugging

      hc_timer_t timer_commit;

      hc_timer_set (&timer_commit);

      hc_thread_mutex_lock (brain_server_db_attack->mux_ag);

      i64 new_attacks = 0;

      for (i64 idx = 0; idx < brain_server_db_attack->short_cnt; idx++)
      {
        if (brain_server_db_attack->short_buf[idx].client_idx == client_idx)
        {
          if (brain_server_db_attack_realloc (brain_server_db_attack, 1, 0) == true)
          {
            brain_server_db_attack->long_buf[brain_server_db_attack->long_cnt].offset = brain_server_db_attack->short_buf[idx].offset;
            brain_server_db_attack->long_buf[brain_server_db_attack->long_cnt].length = brain_server_db_attack->short_buf[idx].length;

            brain_server_db_attack->long_cnt++;

            qsort (brain_server_db_attack->long_buf, brain_server_db_attack->long_cnt, sizeof (brain_server_attack_long_t), brain_server_sort_attack_long);
          }
          else
          {
            brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);
          }

          brain_server_db_attack->short_buf[idx].offset     = 0;
          brain_server_db_attack->short_buf[idx].length     = 0;
          brain_server_db_attack->short_buf[idx].client_idx = 0;

          new_attacks++;
        }
      }

      brain_server_db_attack->write_attacks = true;

      hc_thread_mutex_unlock (brain_server_db_attack->mux_ag);

      if (new_attacks)
      {
        const double ms_attacks = hc_timer_get (timer_commit);

        brain_logging (stdout, client_idx, "C | %8.2f ms | Attacks: %" PRIi64 "\n", ms_attacks, new_attacks);
      }

      // time the lookups for debugging

      hc_timer_set (&timer_commit);

      hc_thread_mutex_lock (brain_server_db_hash->mux_hg);

      // long-term memory merge

      if (brain_server_db_short->short_cnt)
      {
        if (brain_server_db_hash_realloc (brain_server_db_hash, brain_server_db_short->short_cnt) == true)
        {
          if (brain_server_db_hash->long_cnt == 0)
          {
            for (i64 idx = 0; idx < brain_server_db_short->short_cnt; idx++)
            {
              brain_server_db_hash->long_buf[idx].hash[0] = brain_server_db_short->short_buf[idx].hash[0];
              brain_server_db_hash->long_buf[idx].hash[1] = brain_server_db_short->short_buf[idx].hash[1];
            }

            brain_server_db_hash->long_cnt = brain_server_db_short->short_cnt;
          }
          else
          {
            const i64 cnt_total = brain_server_db_hash->long_cnt + brain_server_db_short->short_cnt;

            i64 long_left  = brain_server_db_hash->long_cnt - 1;
            i64 short_left = brain_server_db_short->short_cnt - 1;
            i64 long_dupes = 0;

            for (i64 idx = cnt_total - 1; idx >= long_dupes; idx--)
            {
              const brain_server_hash_long_t  *long_entry  = &brain_server_db_hash->long_buf[long_left];
              const brain_server_hash_short_t *short_entry = &brain_server_db_short->short_buf[short_left];

              int rc = 0;

              if ((long_left >= 0) && (short_left >= 0))
              {
                rc = brain_server_sort_hash (long_entry->hash, short_entry->hash);
              }
              else if (long_left >= 0)
              {
                rc = 1;
              }
              else if (short_left >= 0)
              {
                rc = -1;
              }
              else
              {
                brain_logging (stderr, client_idx, "unexpected remaining buffers in compare: %" PRIi64 " - %" PRIi64 "\n", long_left, short_left);
              }

              brain_server_hash_long_t *next = &brain_server_db_hash->long_buf[idx];

              if (rc == -1)
              {
                next->hash[0] = short_entry->hash[0];
                next->hash[1] = short_entry->hash[1];

                short_left--;
              }
              else if (rc == 1)
              {
                next->hash[0] = long_entry->hash[0];
                next->hash[1] = long_entry->hash[1];

                long_left--;
              }
              else
              {
                next->hash[0] = long_entry->hash[0];
                next->hash[1] = long_entry->hash[1];

                short_left--;
                long_left--;

                long_dupes++;
              }
            }

            if ((long_left != -1) || (short_left != -1))
            {
              brain_logging (stderr, client_idx, "unexpected remaining buffers in commit: %" PRIi64 " - %" PRIi64 "\n", long_left, short_left);
            }

            brain_server_db_hash->long_cnt = cnt_total - long_dupes;

            if (long_dupes)
            {
              for (i64 idx = 0; idx < brain_server_db_hash->long_cnt; idx++)
              {
                brain_server_db_hash->long_buf[idx].hash[0] = brain_server_db_hash->long_buf[long_dupes + idx].hash[0];
                brain_server_db_hash->long_buf[idx].hash[1] = brain_server_db_hash->long_buf[long_dupes + idx].hash[1];
              }
            }
          }
        }
        else
        {
          brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);
        }

        brain_server_db_hash->write_hashes = true;
      }

      hc_thread_mutex_unlock (brain_server_db_hash->mux_hg);

      if (brain_server_db_short->short_cnt)
      {
        const double ms_hashes = hc_timer_get (timer_commit);

        brain_logging (stdout, client_idx, "C | %8.2f ms | Hashes: %" PRIi64 "\n", ms_hashes, brain_server_db_short->short_cnt);
      }

      brain_server_db_short->short_cnt = 0;
    }
    else if (operation == BRAIN_OPERATION_HASH_LOOKUP)
    {
      int in_size = 0;

      if (brain_recv (client_fd, &in_size, sizeof (in_size), 0, NULL, NULL) == false) break;

      if (in_size == 0)
      {
        brain_logging (stderr, client_idx, "Zero in_size value\n");

        break;
      }

      if (in_size > (int) recv_size) break;

      if (brain_recv (client_fd, recv_buf, (size_t) in_size, 0, NULL, NULL) == false) break;

      const int hashes_cnt = in_size / BRAIN_HASH_SIZE;

      if (hashes_cnt == 0)
      {
        brain_logging (stderr, client_idx, "Zero passwords\n");

        break;
      }

      if ((brain_server_db_short->short_cnt + hashes_cnt) > passwords_max)
      {
        brain_logging (stderr, client_idx, "Too many passwords\n");

        break;
      }

      // time the lookups for debugging

      hc_timer_t timer_lookup;

      hc_timer_set (&timer_lookup);

      // make it easier to work with

      for (int hash_idx = 0, recv_idx = 0; hash_idx < hashes_cnt; hash_idx += 1, recv_idx += 2)
      {
        temp_buf[hash_idx].hash[0] = recv_buf[recv_idx + 0];
        temp_buf[hash_idx].hash[1] = recv_buf[recv_idx + 1];

        temp_buf[hash_idx].hash_idx = hash_idx;

        send_buf[hash_idx] = 0;
      }

      // unique temp memory

      i64 temp_cnt = 0;

      qsort (temp_buf, hashes_cnt, sizeof (brain_server_hash_unique_t), brain_server_sort_hash_unique);

      brain_server_hash_unique_t *prev = temp_buf + temp_cnt;

      for (i64 temp_idx = 1; temp_idx < hashes_cnt; temp_idx++)
      {
        brain_server_hash_unique_t *cur = temp_buf + temp_idx;

        if ((cur->hash[0] == prev->hash[0]) && (cur->hash[1] == prev->hash[1]))
        {
          send_buf[cur->hash_idx] = 1;
        }
        else
        {
          temp_cnt++;

          prev = temp_buf + temp_cnt;

          prev->hash[0] = cur->hash[0];
          prev->hash[1] = cur->hash[1];

          prev->hash_idx = cur->hash_idx; // we need this in a later stage
        }
      }

      temp_cnt++;

      // check if they are in long term memory

      hc_thread_mutex_lock (brain_server_db_hash->mux_hr);

      brain_server_db_hash->hb++;

      if (brain_server_db_hash->hb == 1)
      {
        hc_thread_mutex_lock (brain_server_db_hash->mux_hg);
      }

      hc_thread_mutex_unlock (brain_server_db_hash->mux_hr);

      if (temp_cnt > 0)
      {
        i64 temp_idx_new = 0;

        for (i64 temp_idx = 0; temp_idx < temp_cnt; temp_idx++)
        {
          brain_server_hash_unique_t *cur = &temp_buf[temp_idx];

          const i64 r = brain_server_find_hash_long (cur->hash, brain_server_db_hash->long_buf, brain_server_db_hash->long_cnt);

          if (r != -1)
          {
            send_buf[cur->hash_idx] = 1;
          }
          else
          {
            brain_server_hash_unique_t *save = temp_buf + temp_idx_new;

            temp_idx_new++;

            save->hash[0] = cur->hash[0];
            save->hash[1] = cur->hash[1];

            save->hash_idx = cur->hash_idx; // we need this in a later stage
          }
        }

        temp_cnt = temp_idx_new;
      }

      hc_thread_mutex_lock (brain_server_db_hash->mux_hr);

      brain_server_db_hash->hb--;

      if (brain_server_db_hash->hb == 0)
      {
        hc_thread_mutex_unlock (brain_server_db_hash->mux_hg);
      }

      hc_thread_mutex_unlock (brain_server_db_hash->mux_hr);

      // check if they are in short term memory

      if (temp_cnt > 0)
      {
        i64 temp_idx_new = 0;

        for (i64 temp_idx = 0; temp_idx < temp_cnt; temp_idx++)
        {
          brain_server_hash_unique_t *cur = &temp_buf[temp_idx];

          const i64 r = brain_server_find_hash_short (cur->hash, brain_server_db_short->short_buf, brain_server_db_short->short_cnt);

          if (r != -1)
          {
            send_buf[cur->hash_idx] = 1;
          }
          else
          {
            brain_server_hash_unique_t *save = temp_buf + temp_idx_new;

            temp_idx_new++;

            save->hash[0] = cur->hash[0];
            save->hash[1] = cur->hash[1];

            save->hash_idx = cur->hash_idx; // we need this in a later stage
          }
        }

        temp_cnt = temp_idx_new;
      }

      // update remaining

      if (temp_cnt > 0)
      {
        if (brain_server_db_short->short_cnt == 0)
        {
          for (i64 idx = 0; idx < temp_cnt; idx++)
          {
            brain_server_db_short->short_buf[idx].hash[0] = temp_buf[idx].hash[0];
            brain_server_db_short->short_buf[idx].hash[1] = temp_buf[idx].hash[1];
          }

          brain_server_db_short->short_cnt = temp_cnt;
        }
        else
        {
          const i64 cnt_total = brain_server_db_short->short_cnt + temp_cnt;

          i64 short_left  = brain_server_db_short->short_cnt - 1;
          i64 unique_left = temp_cnt - 1;

          for (i64 idx = cnt_total - 1; idx >= 0; idx--)
          {
            const brain_server_hash_short_t  *short_entry  = brain_server_db_short->short_buf + short_left;
            const brain_server_hash_unique_t *unique_entry = temp_buf + unique_left;

            int rc = 0;

            if ((short_left >= 0) && (unique_left >= 0))
            {
              rc = brain_server_sort_hash (short_entry->hash, unique_entry->hash);
            }
            else if (short_left >= 0)
            {
              rc = 1;
            }
            else if (unique_left >= 0)
            {
              rc = -1;
            }
            else
            {
              brain_logging (stderr, client_idx, "unexpected remaining buffers in compare: %" PRIi64 " - %" PRIi64 "\n", short_left, unique_left);
            }

            brain_server_hash_short_t *next = brain_server_db_short->short_buf + idx;

            if (rc == -1)
            {
              next->hash[0] = unique_entry->hash[0];
              next->hash[1] = unique_entry->hash[1];

              unique_left--;
            }
            else if (rc == 1)
            {
              next->hash[0] = short_entry->hash[0];
              next->hash[1] = short_entry->hash[1];

              short_left--;
            }
            else
            {
              brain_logging (stderr, client_idx, "unexpected zero comparison in commit\n");
            }
          }

          if ((short_left != -1) || (unique_left != -1))
          {
            brain_logging (stderr, client_idx, "unexpected remaining buffers in commit: %" PRIi64 " - %" PRIi64 "\n", short_left, unique_left);
          }

          brain_server_db_short->short_cnt = cnt_total;
        }
      }

      // opportunity to set counters for stats

      int local_lookup_new = 0;

      for (i64 hashes_idx = 0; hashes_idx < hashes_cnt; hashes_idx++)
      {
        if (send_buf[hashes_idx] == 0)
        {
          local_lookup_new++;
        }
      }

      // needs anti-flood fix

      const double ms = hc_timer_get (timer_lookup);

      brain_logging (stdout, client_idx, "L | %8.2f ms | Long: %" PRIi64 ", Inc: %d, New: %d\n", ms, brain_server_db_hash->long_cnt, hashes_cnt, local_lookup_new);

      // send

      int out_size = hashes_cnt;

      if (brain_send (client_fd, &out_size, sizeof (out_size), SEND_FLAGS, NULL, NULL) == false) break;
      if (brain_send (client_fd, send_buf,           out_size, SEND_FLAGS, NULL, NULL) == false) break;
    }
    else
    {
      break;
    }
  }

  // client reservations

  hc_thread_mutex_lock (brain_server_db_attack->mux_ag);

  for (i64 idx = 0; idx < brain_server_db_attack->short_cnt; idx++)
  {
    if (brain_server_db_attack->short_buf[idx].client_idx == client_idx)
    {
      brain_server_db_attack->short_buf[idx].offset     = 0;
      brain_server_db_attack->short_buf[idx].length     = 0;
      brain_server_db_attack->short_buf[idx].client_idx = 0;
    }
  }

  hc_thread_mutex_unlock (brain_server_db_attack->mux_ag);

  // short free

  hcfree (brain_server_db_short->short_buf);
  hcfree (brain_server_db_short);

  // free local memory

  hcfree (send_buf);
  hcfree (temp_buf);
  hcfree (recv_buf);

  brain_logging (stdout, client_idx, "Disconnected\n");

  brain_server_dbs->client_slots[client_idx] = 0;

  close (client_fd);

  return NULL;
}

i64 brain_server_find_hash_long (const u32 *search, const brain_server_hash_long_t *buf, const i64 cnt)
{
  return -1;
}

i64 brain_server_find_hash_short (const u32 *search, const brain_server_hash_short_t *buf, const i64 cnt)
{
  return -1;
}

void brain_server_db_attack_init (brain_server_db_attack_t *brain_server_db_attack, const u32 brain_attack)
{
  brain_server_db_attack->brain_attack = brain_attack;

  brain_server_db_attack->ab            = 0;
  brain_server_db_attack->short_cnt     = 0;
  brain_server_db_attack->short_buf     = NULL;
  brain_server_db_attack->short_alloc   = 0;
  brain_server_db_attack->long_cnt      = 0;
  brain_server_db_attack->long_buf      = NULL;
  brain_server_db_attack->long_alloc    = 0;
  brain_server_db_attack->write_attacks = false;

  hc_thread_mutex_init (brain_server_db_attack->mux_ar);
  hc_thread_mutex_init (brain_server_db_attack->mux_ag);
}

bool brain_server_db_attack_realloc (brain_server_db_attack_t *brain_server_db_attack, const i64 new_long_cnt, const i64 new_short_cnt)
{
  if ((brain_server_db_attack->long_cnt + new_long_cnt) > brain_server_db_attack->long_alloc)
  {
    const i64 realloc_size_total = (i64) mydivc64 ((const u64) new_long_cnt, (const u64) BRAIN_SERVER_REALLOC_ATTACK_SIZE) * BRAIN_SERVER_REALLOC_ATTACK_SIZE;

    brain_server_attack_long_t *long_buf = (brain_server_attack_long_t *) hcrealloc (brain_server_db_attack->long_buf, brain_server_db_attack->long_alloc * sizeof (brain_server_attack_long_t), realloc_size_total * sizeof (brain_server_attack_long_t));

    if (long_buf == NULL) return false;

    brain_server_db_attack->long_buf    = long_buf;
    brain_server_db_attack->long_alloc += realloc_size_total;
  }

  if ((brain_server_db_attack->short_cnt + new_short_cnt) > brain_server_db_attack->short_alloc)
  {
    const i64 realloc_size_total = (i64) mydivc64 ((const u64) new_short_cnt, (const u64) BRAIN_SERVER_REALLOC_ATTACK_SIZE) * BRAIN_SERVER_REALLOC_ATTACK_SIZE;

    brain_server_attack_short_t *short_buf = (brain_server_attack_short_t *) hcrealloc (brain_server_db_attack->short_buf, brain_server_db_attack->short_alloc * sizeof (brain_server_attack_short_t), realloc_size_total * sizeof (brain_server_attack_short_t));

    if (short_buf == NULL) return false;

    brain_server_db_attack->short_buf    = short_buf;
    brain_server_db_attack->short_alloc += realloc_size_total;
  }

  return true;
}


void brain_server_db_hash_init (brain_server_db_hash_t *brain_server_db_hash, const u32 brain_session)
{
  brain_server_db_hash->brain_session = brain_session;

  brain_server_db_hash->hb           = 0;
  brain_server_db_hash->long_cnt     = 0;
  brain_server_db_hash->long_buf     = NULL;
  brain_server_db_hash->long_alloc   = 0;
  brain_server_db_hash->write_hashes = false;

  hc_thread_mutex_init (brain_server_db_hash->mux_hr);
  hc_thread_mutex_init (brain_server_db_hash->mux_hg);
}
u64 brain_server_highest_attack_short (const brain_server_attack_short_t *buf, const i64 cnt, const u64 start)
{
  return start;
}

u64 brain_server_find_attack_long (const brain_server_attack_long_t *buf, const i64 cnt, const u64 offset, const u64 length)
{
  return 0;
}

u64 brain_server_find_attack_short (const brain_server_attack_short_t *buf, const i64 cnt, const u64 offset, const u64 length)
{
  return 0;
}

int brain_server_sort_db_hash (const void *v1, const void *v2)
{
  const brain_server_db_hash_t *d1 = (const brain_server_db_hash_t *) v1;
  const brain_server_db_hash_t *d2 = (const brain_server_db_hash_t *) v2;

  if (d1->brain_session > d2->brain_session) return  1;
  if (d1->brain_session < d2->brain_session) return -1;

  return 0;
}

int brain_server_sort_db_attack (const void *v1, const void *v2)
{
  const brain_server_db_attack_t *d1 = (const brain_server_db_attack_t *) v1;
  const brain_server_db_attack_t *d2 = (const brain_server_db_attack_t *) v2;

  if (d1->brain_attack > d2->brain_attack) return  1;
  if (d1->brain_attack < d2->brain_attack) return -1;

  return 0;
}

int brain_server_sort_hash (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  if (d1[1] > d2[1]) return  1;
  if (d1[1] < d2[1]) return -1;
  if (d1[0] > d2[0]) return  1;
  if (d1[0] < d2[0]) return -1;

  return 0;
}

int brain_server_sort_attack_long (const void *v1, const void *v2)
{
  const brain_server_attack_long_t *d1 = (const brain_server_attack_long_t *) v1;
  const brain_server_attack_long_t *d2 = (const brain_server_attack_long_t *) v2;

  if (d1->offset > d2->offset) return  1;
  if (d1->offset < d2->offset) return -1;

  return 0;
}

int brain_server_sort_attack_short (const void *v1, const void *v2)
{
  const brain_server_attack_short_t *d1 = (const brain_server_attack_short_t *) v1;
  const brain_server_attack_short_t *d2 = (const brain_server_attack_short_t *) v2;

  if (d1->offset > d2->offset) return  1;
  if (d1->offset < d2->offset) return -1;

  return 0;
}

int brain_server_sort_hash_long (const void *v1, const void *v2)
{
  const brain_server_hash_long_t *d1 = (const brain_server_hash_long_t *) v1;
  const brain_server_hash_long_t *d2 = (const brain_server_hash_long_t *) v2;

  return brain_server_sort_hash (d1->hash, d2->hash);
}

int brain_server_sort_hash_short (const void *v1, const void *v2)
{
  const brain_server_hash_short_t *d1 = (const brain_server_hash_short_t *) v1;
  const brain_server_hash_short_t *d2 = (const brain_server_hash_short_t *) v2;

  return brain_server_sort_hash (d1->hash, d2->hash);
}

int brain_server_sort_hash_unique (const void *v1, const void *v2)
{
  const brain_server_hash_unique_t *d1 = (const brain_server_hash_unique_t *) v1;
  const brain_server_hash_unique_t *d2 = (const brain_server_hash_unique_t *) v2;

  return brain_server_sort_hash (d1->hash, d2->hash);
}

void brain_server_db_attack_free (brain_server_db_attack_t *brain_server_db_attack)
{
  hc_thread_mutex_delete (brain_server_db_attack->mux_ag);
  hc_thread_mutex_delete (brain_server_db_attack->mux_ar);

  hcfree (brain_server_db_attack->long_buf);
  hcfree (brain_server_db_attack->short_buf);

  brain_server_db_attack->ab            = 0;
  brain_server_db_attack->long_cnt      = 0;
  brain_server_db_attack->long_buf      = NULL;
  brain_server_db_attack->long_alloc    = 0;
  brain_server_db_attack->short_cnt     = 0;
  brain_server_db_attack->short_buf     = NULL;
  brain_server_db_attack->short_alloc   = 0;
  brain_server_db_attack->brain_attack  = 0;
  brain_server_db_attack->write_attacks = false;
}

HC_API_CALL void *brain_server_handle_dumps (void *p)
{
  brain_server_dumper_options_t *brain_server_dumper_options = (brain_server_dumper_options_t *) p;

  brain_server_dbs_t *brain_server_dbs = brain_server_dumper_options->brain_server_dbs;

  u32 brain_server_timer = brain_server_dumper_options->brain_server_timer;

  if (brain_server_timer == 0) return NULL;

  u32 i = 0;

  while (keep_running == true)
  {
    if (i == brain_server_timer)
    {
      brain_server_write_hash_dumps   (brain_server_dbs, ".");
      brain_server_write_attack_dumps (brain_server_dbs, ".");

      i = 0;
    }
    else
    {
      i++;
    }

    sleep (1);
  }

  return NULL;
}

bool brain_server_write_hash_dumps (brain_server_dbs_t *brain_server_dbs, const char *path)
{
  for (i64 idx = 0; idx < brain_server_dbs->hash_cnt; idx++)
  {
    brain_server_db_hash_t *brain_server_db_hash = &brain_server_dbs->hash_buf[idx];

    hc_thread_mutex_lock (brain_server_db_hash->mux_hg);

    char file[100];

    memset (file, 0, sizeof (file));

    snprintf (file, sizeof (file), "%s/brain.%08x.ldmp", path, brain_server_db_hash->brain_session);

    brain_server_write_hash_dump (brain_server_db_hash, file);

    hc_thread_mutex_unlock (brain_server_db_hash->mux_hg);
  }

  return true;
}

bool brain_server_write_attack_dumps (brain_server_dbs_t *brain_server_dbs, const char *path)
{
  for (i64 idx = 0; idx < brain_server_dbs->attack_cnt; idx++)
  {
    brain_server_db_attack_t *brain_server_db_attack = &brain_server_dbs->attack_buf[idx];

    hc_thread_mutex_lock (brain_server_db_attack->mux_ag);

    char file[100];

    memset (file, 0, sizeof (file));

    snprintf (file, sizeof (file), "%s/brain.%08x.admp", path, brain_server_db_attack->brain_attack);

    brain_server_write_attack_dump (brain_server_db_attack, file);

    hc_thread_mutex_unlock (brain_server_db_attack->mux_ag);
  }

  return true;
}
bool brain_server_read_attack_dump (brain_server_db_attack_t *brain_server_db_attack, const char *file)
{
  hc_timer_t timer_dump;

  hc_timer_set (&timer_dump);

  // read from file

  struct stat sb;

  memset (&sb, 0, sizeof (struct stat));

  if (stat (file, &sb) == -1)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  HCFILE fp;

  if (hc_fopen (&fp, file, "rb") == false)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  i64 temp_cnt = (u64) sb.st_size / sizeof (brain_server_attack_long_t);

  if (brain_server_db_attack_realloc (brain_server_db_attack, temp_cnt, 0) == false)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    hc_fclose (&fp);

    return false;
  }

  const size_t nread = hc_fread (brain_server_db_attack->long_buf, sizeof (brain_server_attack_long_t), temp_cnt, &fp);

  if (nread != (size_t) temp_cnt)
  {
    brain_logging (stderr, 0, "%s: only %" PRIu64 " bytes read\n", file, (u64) nread * sizeof (brain_server_attack_long_t));

    hc_fclose (&fp);

    return false;
  }

  brain_server_db_attack->long_cnt      = temp_cnt;
  brain_server_db_attack->write_attacks = false;

  hc_fclose (&fp);

  const double ms = hc_timer_get (timer_dump);

  brain_logging (stdout, 0, "Read %" PRIu64 " bytes from attack 0x%08x in %.2f ms\n", (u64) sb.st_size, brain_server_db_attack->brain_attack, ms);

  return true;
}
bool brain_server_write_attack_dump (brain_server_db_attack_t *brain_server_db_attack, const char *file)
{
  if (brain_server_db_attack->write_attacks == false) return true;

  hc_timer_t timer_dump;

  hc_timer_set (&timer_dump);

  // write to file

  HCFILE fp;

  if (hc_fopen (&fp, file, "wb") == false)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  // storing should not include reserved attacks only finished

  const size_t nwrite = hc_fwrite (brain_server_db_attack->long_buf, sizeof (brain_server_attack_long_t), brain_server_db_attack->long_cnt, &fp);

  if (nwrite != (size_t) brain_server_db_attack->long_cnt)
  {
    brain_logging (stderr, 0, "%s: only %" PRIu64 " bytes written\n", file, (u64) nwrite * sizeof (brain_server_attack_long_t));

    hc_fclose (&fp);

    return false;
  }

  hc_fclose (&fp);

  brain_server_db_attack->write_attacks = false;

  // stats

  const double ms = hc_timer_get (timer_dump);

  struct stat sb;

  memset (&sb, 0, sizeof (struct stat));

  if (stat (file, &sb) == -1)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  brain_logging (stdout, 0, "Wrote %" PRIu64 " bytes from attack 0x%08x in %.2f ms\n", (u64) sb.st_size, brain_server_db_attack->brain_attack, ms);

  return true;
}
bool brain_server_read_hash_dump (brain_server_db_hash_t *brain_server_db_hash, const char *file)
{
  hc_timer_t timer_dump;

  hc_timer_set (&timer_dump);

  // read from file

  struct stat sb;

  memset (&sb, 0, sizeof (struct stat));

  if (stat (file, &sb) == -1)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  HCFILE fp;

  if (hc_fopen (&fp, file, "rb") == false)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  i64 temp_cnt = (u64) sb.st_size / sizeof (brain_server_hash_long_t);

  if (brain_server_db_hash_realloc (brain_server_db_hash, temp_cnt) == false)
  {
    brain_logging (stderr, 0, "%s\n", MSG_ENOMEM);

    hc_fclose (&fp);

    return false;
  }

  const size_t nread = hc_fread (brain_server_db_hash->long_buf, sizeof (brain_server_hash_long_t), temp_cnt, &fp);

  if (nread != (size_t) temp_cnt)
  {
    brain_logging (stderr, 0, "%s: only %" PRIu64 " bytes read\n", file, (u64) nread * sizeof (brain_server_hash_long_t));

    hc_fclose (&fp);

    return false;
  }

  brain_server_db_hash->long_cnt     = temp_cnt;
  brain_server_db_hash->write_hashes = false;

  hc_fclose (&fp);

  const double ms = hc_timer_get (timer_dump);

  brain_logging (stdout, 0, "Read %" PRIu64 " bytes from session 0x%08x in %.2f ms\n", (u64) sb.st_size, brain_server_db_hash->brain_session, ms);

  return true;
}

u64 brain_server_highest_attack (const brain_server_db_attack_t *buf)
{
  const brain_server_attack_long_t  *long_buf  = buf->long_buf;
  const brain_server_attack_short_t *short_buf = buf->short_buf;

  const u64 long_cnt  = buf->long_cnt;
  const u64 short_cnt = buf->short_cnt;

  u64 highest_long  = brain_server_highest_attack_long  (long_buf,  long_cnt,  0);
  u64 highest_short = brain_server_highest_attack_short (short_buf, short_cnt, 0);

  u64 highest = MAX (highest_long, highest_short);

  highest_long  = brain_server_highest_attack_long  (long_buf,  long_cnt,  highest);
  highest_short = brain_server_highest_attack_short (short_buf, short_cnt, highest);

  highest = MAX (highest_long, highest_short);

  return highest;
}

u64 brain_server_highest_attack_long (const brain_server_attack_long_t *buf, const i64 cnt, const u64 start)
{
  return start;
}

void brain_server_db_hash_free (brain_server_db_hash_t *brain_server_db_hash)
{
  hc_thread_mutex_delete (brain_server_db_hash->mux_hg);
  hc_thread_mutex_delete (brain_server_db_hash->mux_hr);

  hcfree (brain_server_db_hash->long_buf);

  brain_server_db_hash->hb            = 0;
  brain_server_db_hash->long_cnt      = 0;
  brain_server_db_hash->long_buf      = NULL;
  brain_server_db_hash->long_alloc    = 0;
  brain_server_db_hash->write_hashes  = false;
  brain_server_db_hash->brain_session = 0;
}

bool brain_server_write_hash_dump (brain_server_db_hash_t *brain_server_db_hash, const char *file)
{
  if (brain_server_db_hash->write_hashes == false) return true;

  hc_timer_t timer_dump;

  hc_timer_set (&timer_dump);

  // write to file

  HCFILE fp;

  if (hc_fopen (&fp, file, "wb") == false)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  const size_t nwrite = hc_fwrite (brain_server_db_hash->long_buf, sizeof (brain_server_hash_long_t), brain_server_db_hash->long_cnt, &fp);

  if (nwrite != (size_t) brain_server_db_hash->long_cnt)
  {
    brain_logging (stderr, 0, "%s: only %" PRIu64 " bytes written\n", file, (u64) nwrite * sizeof (brain_server_hash_long_t));

    hc_fclose (&fp);

    return false;
  }

  hc_fclose (&fp);

  brain_server_db_hash->write_hashes = false;

  // stats

  const double ms = hc_timer_get (timer_dump);

  struct stat sb;

  memset (&sb, 0, sizeof (struct stat));

  if (stat (file, &sb) == -1)
  {
    brain_logging (stderr, 0, "%s: %s\n", file, strerror (errno));

    return false;
  }

  brain_logging (stdout, 0, "Wrote %" PRIu64 " bytes from session 0x%08x in %.2f ms\n", (u64) sb.st_size, brain_server_db_hash->brain_session, ms);

  return true;
}

void brain_server_handle_signal (int signo)
{
  if (signo == SIGINT)
  {
    keep_running = false;
  }
}

int brain_server (const char *listen_host, const int listen_port, const char *brain_password, const char *brain_session_whitelist, const u32 brain_server_timer)
{
  int rc = 0;

  if (listen_port < 1 || listen_port > 65535)
  {
    brain_logging (stderr, 0, "Invalid port number specified\n");
    return -1;
  }

  signal (SIGINT, brain_server_handle_signal);

  brain_server_dbs_t brain_server_dbs;
  memset (&brain_server_dbs, 0, sizeof (brain_server_dbs));

  if (hc_thread_mutex_init (mux_display) == -1)
  {
    brain_logging (stderr, 0, "hc_thread_mutex_init(): %s\n", strerror (errno));
    return -1;
  }

  brain_server_dbs.client_slots = (int *) hccalloc (BRAIN_SERVER_CLIENTS_MAX, sizeof (int));

  // load dumps

  if (brain_server_read_hash_dumps (&brain_server_dbs, ".") == false)
  {
    rc = -1;
    goto cleanup;
  }

  if (brain_server_read_attack_dumps (&brain_server_dbs, ".") == false)
  {
    rc = -1;
    goto cleanup;
  }

  // socket stuff

  int server_fd;

  if ((server_fd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
  {
    brain_logging (stderr, 0, "socket: %s\n", strerror (errno));
    rc = -1;
    goto cleanup;
  }

  const int opt = 1;

  if (setsockopt (server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt)) == -1)
  {
    brain_logging (stderr, 0, "setsockopt: %s\n", strerror (errno));
    rc = -1;
    goto cleanup;
  }

  struct sockaddr_in sa;

  memset (&sa, 0, sizeof (sa));

  sa.sin_family = AF_INET;
  sa.sin_port = htons (listen_port);

  if (listen_host)
  {
    if (inet_pton (AF_INET, listen_host, &sa.sin_addr) != 1)
    {
      brain_logging (stderr, 0, "%s: Failed to resolve\n", listen_host);
      rc = -1;
      goto cleanup;
    }
  }
  else
  {
    sa.sin_addr.s_addr = INADDR_ANY;
  }

  if (bind (server_fd, (struct sockaddr *) &sa, sizeof (sa)) == -1)
  {
    brain_logging (stderr, 0, "bind: %s\n", strerror (errno));
    rc = -1;
    goto cleanup;
  }

  if (listen (server_fd, SOMAXCONN) == -1)
  {
    brain_logging (stderr, 0, "listen: %s\n", strerror (errno));
    rc = -1;
    goto cleanup;
  }

  // start dumper thread

  brain_server_dumper_options_t brain_server_dumper_options;

  brain_server_dumper_options.brain_server_dbs   = &brain_server_dbs;
  brain_server_dumper_options.brain_server_timer = brain_server_timer;

  hc_thread_t dumper_thread;

  hc_thread_create (dumper_thread, brain_server_handle_dumps, &brain_server_dumper_options);

  // client handling

  while (keep_running == true)
  {
    struct sockaddr_in ca;
    socklen_t cal = sizeof (ca);

    const int client_fd = accept (server_fd, (struct sockaddr *) &ca, &cal);

    if (client_fd == -1)
    {
      brain_logging (stderr, 0, "accept: %s\n", strerror (errno));
      rc = -1;
      goto cleanup;
    }

    char *client_ip = inet_ntoa (ca.sin_addr);

    const int client_idx = brain_server_get_client_idx (&brain_server_dbs);

    if (client_idx == -1)
    {
      brain_logging (stderr, client_idx, "Maximum number of connections reached\n");
      close (client_fd);
      continue;
    }

    brain_logging (stdout, client_idx, "IP: %s\n", client_ip);

    brain_server_client_options_t brain_server_client_options;

    brain_server_client_options.brain_server_dbs = &brain_server_dbs;
    brain_server_client_options.client_idx       = client_idx;
    brain_server_client_options.client_fd        = client_fd;
    brain_server_client_options.auth_password    = (char *) brain_password;

    hc_thread_t client_thread;

    hc_thread_create (client_thread, brain_server_handle_client, &brain_server_client_options);
  }

cleanup:
  if (brain_server_dbs.client_slots) hcfree (brain_server_dbs.client_slots);

  hc_thread_mutex_delete (mux_display);

  for (int hash_idx = 0; hash_idx < brain_server_dbs.hash_cnt; hash_idx++)
  {
    brain_server_db_hash_t *brain_server_db = &brain_server_dbs.hash_buf[hash_idx];

    brain_server_db_hash_free (brain_server_db);
  }

  for (int attack_idx = 0; attack_idx < brain_server_dbs.attack_cnt; attack_idx++)
  {
    brain_server_db_attack_t *brain_server_db = &brain_server_dbs.attack_buf[attack_idx];

    brain_server_db_attack_free (brain_server_db);
  }

  return rc;
}

int brain_server_get_client_idx (brain_server_dbs_t *brain_server_dbs)
{
  for (int i = 1; i < BRAIN_SERVER_CLIENTS_MAX; i++)
  {
    if (brain_server_dbs->client_slots[i] == 0)
    {
      brain_server_dbs->client_slots[i] = 1;

      return i;
    }
  }

  return -1;
}

bool brain_server_read_attack_dumps (brain_server_dbs_t *brain_server_dbs, const char *path)
{
  brain_server_dbs->attack_cnt = 0;

  /* temporary disabled due to https://github.com/hashcat/hashcat/issues/2379
  if (chdir (path) == -1)
  {
    brain_logging (stderr, 0, "%s: %s\n", path, strerror (errno));

    return false;
  }
  */

  DIR *dirp = opendir (path);

  if (dirp == NULL)
  {
    brain_logging (stderr, 0, "%s: %s\n", path, strerror (errno));

    return false;
  }

  struct dirent *entry = NULL;

  while ((entry = readdir (dirp)) != NULL)
  {
    char *file = entry->d_name;

    const size_t len = strlen (file);

    if (len != 19) continue;

    if (file[ 0] != 'b') continue;
    if (file[ 1] != 'r') continue;
    if (file[ 2] != 'a') continue;
    if (file[ 3] != 'i') continue;
    if (file[ 4] != 'n') continue;
    if (file[ 5] != '.') continue;

    if (file[14] != '.') continue;
    if (file[15] != 'a') continue;
    if (file[16] != 'd') continue;
    if (file[17] != 'm') continue;
    if (file[18] != 'p') continue;

    const u32 brain_attack = byte_swap_32 (hex_to_u32 ((const u8 *) file + 6));

    brain_server_db_attack_t *brain_server_db_attack = &brain_server_dbs->attack_buf[brain_server_dbs->attack_cnt];

    brain_server_db_attack_init (brain_server_db_attack, brain_attack);

    if (brain_server_read_attack_dump (brain_server_db_attack, file) == false) continue;

    brain_server_dbs->attack_cnt++;
  }

  closedir (dirp);

  return true;
}

bool brain_server_read_hash_dumps (brain_server_dbs_t *brain_server_dbs, const char *path)
{
  brain_server_dbs->hash_cnt = 0;

  /* temporary disabled due to https://github.com/hashcat/hashcat/issues/2379
  if (chdir (path) == -1)
  {
    brain_logging (stderr, 0, "%s: %s\n", path, strerror (errno));

    return false;
  }
  */

  DIR *dirp = opendir (path);

  if (dirp == NULL)
  {
    brain_logging (stderr, 0, "%s: %s\n", path, strerror (errno));

    return false;
  }

  struct dirent *entry;

  while ((entry = readdir (dirp)) != NULL)
  {
    char *file = entry->d_name;

    const size_t len = strlen (file);

    if (len != 19) continue;

    if (file[ 0] != 'b') continue;
    if (file[ 1] != 'r') continue;
    if (file[ 2] != 'a') continue;
    if (file[ 3] != 'i') continue;
    if (file[ 4] != 'n') continue;
    if (file[ 5] != '.') continue;

    if (file[14] != '.') continue;
    if (file[15] != 'l') continue;
    if (file[16] != 'd') continue;
    if (file[17] != 'm') continue;
    if (file[18] != 'p') continue;

    const u32 brain_session = byte_swap_32 (hex_to_u32 ((const u8 *) file + 6));

    brain_server_db_hash_t *brain_server_db_hash = &brain_server_dbs->hash_buf[brain_server_dbs->hash_cnt];

    brain_server_db_hash_init (brain_server_db_hash, brain_session);

    if (brain_server_read_hash_dump (brain_server_db_hash, file) == false) continue;

    brain_server_dbs->hash_cnt++;
  }

  closedir (dirp);

  return true;
}
bool brain_server_db_hash_realloc (brain_server_db_hash_t *brain_server_db_hash, const i64 new_long_cnt)
{
  if ((brain_server_db_hash->long_cnt + new_long_cnt) > brain_server_db_hash->long_alloc)
  {
    const i64 realloc_size_total = (i64) mydivc64 ((const u64) new_long_cnt, (const u64) BRAIN_SERVER_REALLOC_HASH_SIZE) * BRAIN_SERVER_REALLOC_HASH_SIZE;

    brain_server_hash_long_t *long_buf = (brain_server_hash_long_t *) hcrealloc (brain_server_db_hash->long_buf, brain_server_db_hash->long_alloc * sizeof (brain_server_hash_long_t), realloc_size_total * sizeof (brain_server_hash_long_t));

    if (long_buf == NULL) return false;

    brain_server_db_hash->long_buf    = long_buf;
    brain_server_db_hash->long_alloc += realloc_size_total;
  }

  return true;
}


