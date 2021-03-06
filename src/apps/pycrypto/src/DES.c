/*
 *  DES.c: DES/3DES support for PyCrypto using LibTomCrypt
 *
 * Written in 2009 by Dwayne C. Litzenberger <dlitz@dlitz.net>
 *
 * ===================================================================
 * The contents of this file are dedicated to the public domain.  To
 * the extent that dedication to the public domain is not available,
 * everyone is granted a worldwide, perpetual, royalty-free,
 * non-exclusive license to exercise all rights associated with the
 * contents of this file for any purpose whatsoever.
 * No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ===================================================================
 *
 * Country of origin: Canada
 */

#include "pycrypto_common.h"

/* Setting this will cause LibTomCrypt to return CRYPT_INVALID_ARG when its
 * assert-like LTC_ARGCHK macro fails. */
#define ARGTYPE 4

/* Include the actial DES implementation */
#include "libtom/tomcrypt_des.c"

#include <assert.h>

typedef struct {
    symmetric_key sk;
} block_state;

static void ltcseterr(int rc)
{
    /* error */
    switch (rc) {
    case CRYPT_INVALID_ARG:
        // PyErr_SetString(PyExc_AssertionError, "CRYPT_INVALID_ARG");
        break;

    case CRYPT_INVALID_KEYSIZE:
#ifdef PCT_DES3_MODULE
        // PyErr_SetString(PyExc_ValueError, "Invalid key size (must be either 16 or 24 bytes long)");
#else
        // PyErr_SetString(PyExc_ValueError, "Invalid key size (must be 8 bytes long)");
#endif
        break;

    case CRYPT_INVALID_ROUNDS:
        // PyErr_SetString(PyExc_ValueError, "Invalid number of rounds specified");
        break;

    default:
        // PyErr_Format(PyExc_RuntimeError,
        //     "unexpected run-time error (LTC#%d)", rc);
        break;
    }
}

static void block_init(block_state *self, unsigned char *key, int keylen)
{
//     int rc;
// #ifdef PCT_DES3_MODULE
//     int i;
//     unsigned char keybuf[24];
//     if (keylen == 16) {
//         /* "Two-key 3DES" mode, where the 3DES key is K1,K2,K1 */
//         for (i = 0; i < 16; i++) {
//             keybuf[i] = key[i];
//         }
//         for (i = 0; i < 8; i++) {
//             keybuf[i+16] = key[i];
//         }
//         rc = des3_setup(keybuf, 24, 0, &self->sk);
//         for (i = 0; i < 24; i++) {  /* TODO: securely zeroize this */
//             keybuf[i] = 0;
//         }
//     } else {
//         rc = des3_setup(key, keylen, 0, &self->sk);
//     }
// #else
//     rc = des_setup(key, keylen, 0, &self->sk);
// #endif
    memset(&self->sk, 0, sizeof(self->sk));
    memcpy(&self->sk, key, keylen);
    // assert(rc == CRYPT_OK);
}

static void block_finalize(block_state *self)
{
}

static void block_encrypt(block_state *self, unsigned char *in, unsigned char *out)
{
    int rc;
#ifdef PCT_DES3_MODULE
    rc = des3_ecb_encrypt(in, out, &self->sk);
#else
    rc = des_ecb_encrypt(in, out, &self->sk);
#endif
    assert(rc == CRYPT_OK);
}

static void block_decrypt(block_state *self, unsigned char *in, unsigned char *out)
{
    int rc;
#ifdef PCT_DES3_MODULE
    rc = des3_ecb_decrypt(in, out, &self->sk);
#else
    rc = des_ecb_decrypt(in, out, &self->sk);
#endif
    assert(rc == CRYPT_OK);
}

#ifdef PCT_DES3_MODULE
# define MODULE_NAME _DES3   /* triple DES */
# define BLOCK_SIZE 8       /* 64-bit block size */
# define KEY_SIZE  0        /* variable key size (can be 128 or 192 bits (including parity) */
#define KEY_LEN 16
#else
# define MODULE_NAME _DES   /* single DES */
# define BLOCK_SIZE 8       /* 64-bit block size */
# define KEY_SIZE  8        /* 64-bit keys (including parity) */
# define KEY_LEN  8        /* 64-bit keys (including parity) */
#endif
#include "block_template.c"
