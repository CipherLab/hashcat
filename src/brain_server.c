/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "brain.h"

static bool keep_running = true;
static hc_timer_t timer_logging;
static hc_thread_mutex_t mux_display;

void brain_server_handle_signal (int signo)
{
  if (signo == SIGINT)
  {
    keep_running = false;
  }
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
      brain_server_write_hash_dumps (brain_server_dbs, ".");
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

// ... [Rest of server functions from brain.c]
