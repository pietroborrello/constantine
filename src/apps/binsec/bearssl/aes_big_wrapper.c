#include "../__libsym__/sym.h"
#include "inc/bearssl.h"
#include <stdint.h>

#define KEY_LEN 240 /* uint32_t skey[60]; => 60 * 4 */
#define N_ROUND 2
#define IV_LEN br_aes_big_BLOCK_SIZE /* 16 bytes */
#define DATA_LEN 32   /* Must be a multiple of block size */

int main(int argc, char *argv[]){  
  br_aes_big_cbcenc_keys ctx = {0};
  ctx.vtable = &br_aes_big_cbcenc_vtable;
  ctx.num_rounds = N_ROUND;
  uint8_t iv[IV_LEN] = {0};
  uint8_t data[DATA_LEN] = {0};

  HIGH_INPUT(KEY_LEN, ctx.skey);
  HIGH_INPUT(DATA_LEN, data);

  br_aes_big_cbcenc_run(&ctx, iv, data, (size_t) DATA_LEN);
  write(1, data, DATA_LEN);
  return 0;
}
