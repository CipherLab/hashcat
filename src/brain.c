/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "brain.h"
#include "brain_client.h"
#include "brain_server.h"
#include "brain_utils.h"

int brain_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  brain_ctx_t    *brain_ctx    = hashcat_ctx->brain_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  #ifdef WITH_BRAIN
  brain_ctx->support = true;


  if (brain_ctx->support == false) return 0;

  if (user_options->brain_client == true)
  {
    brain_ctx->enabled = true;
  }

  if (user_options->brain_server == true)
  {
    brain_ctx->enabled = true;
  }
  #else
  brain_ctx->support = false;
  #endif

  return 0;
}

void brain_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  brain_ctx_t *brain_ctx = hashcat_ctx->brain_ctx;

  if (brain_ctx->support == false) return;

  memset (brain_ctx, 0, sizeof (brain_ctx_t));
}
