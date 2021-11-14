#include "constant_time_locl.h"
#include <string.h>

#define MAX_HASH_BLOCK_SIZE 128

typedef struct ssl3_record_st {
    unsigned int length;
    unsigned char *data;    
    int type;
    unsigned char *input;
} SSL3_RECORD;

typedef struct ssl3_state_st {
    long flags;
    unsigned char read_sequence[8];
} SSL3_STATE;

typedef struct evp_cipher_st {
    unsigned long flags;
} EVP_CIPHER;

typedef struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
} EVP_CIPHER_CTX;

typedef struct ssl_st {
    char *expand;
    unsigned long options;
    struct ssl3_state_st *s3;   
    EVP_CIPHER_CTX *enc_read_ctx; 
    int slicing_cheat;
} SSL;

# define SSL_OP_TLS_BLOCK_PADDING_BUG       0x00000200L
# define TLS1_FLAGS_TLS_PADDING_BUG         0x0008
# define SSL_USE_EXPLICIT_IV(a) (a->slicing_cheat&1) // slicing
# define EVP_CIPHER_flags(e)        ((e)->flags)
# define EVP_CIPH_FLAG_AEAD_CIPHER       0x200000
# define EVP_MAX_MD_SIZE                 64/* longest known is SHA512 */
# define OPENSSL_assert(a) 1; // slicing

int CRYPTO_memcmp(const unsigned char *in_a, const char *in_b, size_t len)
{
    size_t i;
    const unsigned char *a = in_a;
    const char *b = in_b;
    unsigned char x = 0;

    for (i = 0; i < len; i++)
        x |= a[i] ^ b[i];

    return x;
}

/*-
 * tls1_cbc_remove_padding removes the CBC padding from the decrypted, TLS, CBC
 * record in |rec| in constant time and returns 1 if the padding is valid and
 * -1 otherwise. It also removes any explicit IV from the start of the record
 * without leaking any timing about whether there was enough space after the
 * padding was removed.
 *
 * block_size: the block size of the cipher used to encrypt the record.
 * returns:
 *   0: (in non-constant time) if the record is publicly invalid.
 *   1: if the padding was valid
 *  -1: otherwise.
 */
int tls1_cbc_remove_padding(const SSL *s,
                            SSL3_RECORD *rec,
                            unsigned bs, unsigned mac_size)
{
  int ii, i, j;
  int l = rec->length;
  ii=i=rec->data[l-1]; /* padding_length */
  i++;
  if (s->options&SSL_OP_TLS_BLOCK_PADDING_BUG)
    {
      /* First packet is even in size, so check */
      if ((*(unsigned long*)s->s3->read_sequence == 0) && !(ii & 1))
        s->s3->flags|=TLS1_FLAGS_TLS_PADDING_BUG;
      if (s->s3->flags & TLS1_FLAGS_TLS_PADDING_BUG)
        i--;
    }
  /* TLS 1.0 does not bound the number of padding bytes by the block size.
   * All of them must have value 'padding_length'. */
  if (i + bs > (int)rec->length)
    {
      /* Incorrect padding. SSLerr() and ssl3_alert are done
       * by caller: we don't want to reveal whether this is
       * a decryption error or a MAC verification failure
       * (see http://www.openssl.org/~bodo/tls-cbc.txt) 
       */
      return -1;
    }
  for (j=(int)(l-i); j<(int)l; j++)
    {
      if (rec->data[j] != ii)
        {
					/* Incorrect padding */
					return -1;
        }
    }
  rec->length-=i;

  rec->data += bs;    /* skip the implicit IV */
  rec->input += bs;
  rec->length -= bs;

  return 1;
}
