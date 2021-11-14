#include "../__libsym__/sym.h"
#include "tls1_cbc_remove_padding_lucky13.c"

#define LEN 63

int main(int argc, char *argv[]){

  unsigned long options;              // public
  long s3_flags;                      // public
  unsigned long flags;                // public
  int slicing_cheat;                  // public                  
  unsigned char data[LEN];            // private (public address)
  unsigned int length = LEN;          // public
  unsigned int block_size;            // public
  unsigned int mac_size;              // public

   // Data is private
  HIGH_INPUT(LEN, data);

  // these lengths are all public
  LOW_INPUT(4, &options);
  LOW_INPUT(4, &s3_flags);
  LOW_INPUT(4, &flags);
  LOW_INPUT(4, &slicing_cheat); // stay away from struct hell
  // LOW_INPUT(4, &block_size);
  block_size = 16;
  LOW_INPUT(4, &mac_size);

  SSL3_STATE s3_obj = { s3_flags };
  //for (int i = 0; i<8;i++) s3_obj.read_sequence[i]=s3_read_sequence[i];
  EVP_CIPHER cipher = { flags };
  EVP_CIPHER_CTX cipher_ctx = { &cipher };
  char dummy_expand;
  // setting the expand field to non-zero deactivates non-constant-time if
  SSL s_obj = { &dummy_expand, options, &s3_obj, &cipher_ctx, slicing_cheat};
  /* SSL s_obj = { NULL, options, &s3_obj, &cipher_ctx, slicing_cheat}; */
  const SSL *s = &s_obj;

  // only the length and data fields are used in the function
  SSL3_RECORD rec_obj = { length, data, 0, NULL };
  SSL3_RECORD *rec = &rec_obj;

  int ret = tls1_cbc_remove_padding(s,rec,block_size,mac_size);
  write(1, data, LEN);
  return 0;
}

// TO VERIFY LOOP ADD IN LINE 1196  assert ($i88 == $i88.shadow);

