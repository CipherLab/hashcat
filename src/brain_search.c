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

i64 brain_server_find_hash_long (const u32 *search, const brain_server_hash_long_t *buf, const i64 cnt)
{
  return -1;
}

i64 brain_server_find_hash_short (const u32 *search, const brain_server_hash_short_t *buf, const i64 cnt)
{
  return -1;
}
u64 brain_server_find_attack_long (const brain_server_attack_long_t *buf, const i64 cnt, const u64 offset, const u64 length)
{
  return 0;
}

u64 brain_server_find_attack_short (const brain_server_attack_short_t *buf, const i64 cnt, const u64 offset, const u64 length)
{
  return 0;
}
