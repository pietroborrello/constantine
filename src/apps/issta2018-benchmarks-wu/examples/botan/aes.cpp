/*
* AES
* (C) 1999-2010,2015 Jack Lloyd
*
* Based on the public domain reference implementation by Paulo Baretto
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <stdint.h>
#include <stddef.h>
#include <vector>
#include <cstring>
#include <unistd.h>


#define CACHE_LINE_SIZE 64

inline uint8_t get_byte(const unsigned n, const uint32_t x) __attribute__((always_inline))
{
   return x >> (n << 3);
}

/**
* Make a uint32_t from four bytes
* @param i0 the first byte
* @param i1 the second byte
* @param i2 the third byte
* @param i3 the fourth byte
* @return i0 || i1 || i2 || i3
*/
inline uint32_t make_uint32(uint8_t i0, uint8_t i1, uint8_t i2, uint8_t i3) __attribute__((always_inline))
{
   return ((static_cast<uint32_t>(i0) << 24) |
           (static_cast<uint32_t>(i1) << 16) |
           (static_cast<uint32_t>(i2) <<  8) |
           (static_cast<uint32_t>(i3)));
}
/**
* Bit rotation left
* @param input the input word
* @param rot the number of bits to rotate
* @return input rotated left by rot bits
*/
template<typename T> inline T rotate_left(T input, size_t rot) __attribute__((always_inline))
{
   rot %= 8 * sizeof(T);
   return static_cast<T>((input << rot) | (input >> (8*sizeof(T)-rot)));;
}

/**
* Bit rotation right
* @param input the input word
* @param rot the number of bits to rotate
* @return input rotated right by rot bits
*/
template<typename T> inline T rotate_right(T input, size_t rot) __attribute__((always_inline))
{
   rot %= 8 * sizeof(T);
   return static_cast<T>((input >> rot) | (input << (8*sizeof(T)-rot)));
}

/**
* Load a big-endian word
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th T of in, as a big-endian value
*/
template<typename T>
inline T load_be(const uint8_t in[], size_t off) __attribute__((always_inline))
{
   in += off * sizeof(T);
   T out = 0;
   for(size_t i = 0; i != sizeof(T); ++i)
      out = (out << 8) | in[i];
   return out;
}

inline void store_be(uint32_t in, uint8_t out[4]) __attribute__((always_inline))
{
   out[0] = get_byte(0, in);
   out[1] = get_byte(1, in);
   out[2] = get_byte(2, in);
   out[3] = get_byte(3, in);
}


//using namespace std;
/*
* This implementation is based on table lookups which are known to be
* vulnerable to timing and cache based side channel attacks. Some
* countermeasures are u//sed which may be helpful in some situations:
*
* - Small tables are used in the first and last rounds.
*
* - The TE and TD tables are computed at runtime to avoid flush+reload
*   attacks using clflush. As different processes will not share the
*   same underlying table data, an attacker can't manipulate another
*   processes cache lines via their shared reference to the library
*   read only segment.
*
* - Each cache line of the lookup tables is accessed at the beginning
*   of each call to encrypt or decrypt. (See the Z variable below)
*
* If available SSSE3 or AES-NI are used instead of this version, as both
* are faster and immune to side channel attacks.
*
* Some AES cache timing papers for reference:
*
* "Software mitigations to hedge AES against cache-based software side
* channel vulnerabilities" https://eprint.iacr.org/2006/052.pdf
*
* "Cache Games - Bringing Access-Based Cache Attacks on AES to Practice"
* http://www.ieee-security.org/TC/SP2011/PAPERS/2011/paper031.pdf
*
* "Cache-Collision Timing Attacks Against AES" Bonneau, Mironov
* http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.88.4753
*/

const uint8_t SE[256] = {
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
   0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
   0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
   0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
   0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
   0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
   0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
   0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
   0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
   0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
   0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
   0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
   0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
   0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
   0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
   0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
   0xB0, 0x54, 0xBB, 0x16 };

const uint8_t SD[256] = {
   0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E,
   0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
   0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32,
   0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
   0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49,
   0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
   0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
   0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
   0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05,
   0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
   0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41,
   0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
   0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8,
   0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
   0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B,
   0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
   0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59,
   0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
   0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D,
   0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
   0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63,
   0x55, 0x21, 0x0C, 0x7D };

inline uint8_t xtime(uint8_t s) __attribute__((always_inline)){ return (s << 1) ^ ((s >> 7) * 0x1B); } 
inline uint8_t xtime4(uint8_t s) __attribute__((always_inline)){ return xtime(xtime(s)); }
inline uint8_t xtime8(uint8_t s) __attribute__((always_inline)){ return xtime(xtime(xtime(s))); }

inline uint8_t xtime3(uint8_t s) __attribute__((always_inline)){ return xtime(s) ^ s; }
inline uint8_t xtime9(uint8_t s) __attribute__((always_inline)){ return xtime8(s) ^ s; }
inline uint8_t xtime11(uint8_t s) __attribute__((always_inline)){ return xtime8(s) ^ xtime(s) ^ s; }
inline uint8_t xtime13(uint8_t s) __attribute__((always_inline)){ return xtime8(s) ^ xtime4(s) ^ s; }
inline uint8_t xtime14(uint8_t s) __attribute__((always_inline)){ return xtime8(s) ^ xtime4(s) ^ xtime(s); }

inline const std::vector<uint32_t> AES_TE() __attribute__((always_inline))
{
   //auto compute_TE = []() -> std::vector<uint32_t> {
      std::vector<uint32_t> TE(1024);
      for(size_t i = 0; i != 256; ++i)
      {
         const uint8_t s = SE[i];
         const uint32_t x = make_uint32(xtime(s), s, s, xtime3(s));

         TE[i] = x;
         TE[i+256] = rotate_right(x, 8);
         TE[i+512] = rotate_right(x, 16);
         TE[i+768] = rotate_right(x, 24);
      }

      return TE;
   // };

   // static const std::vector<uint32_t> TE = compute_TE();
   // return TE;
}

inline const std::vector<uint32_t>& AES_TD() __attribute__((always_inline))
{
   // auto compute_TD = []() -> std::vector<uint32_t> {
      std::vector<uint32_t> TD(1024);
      for(size_t i = 0; i != 256; ++i)
      {
         const uint8_t s = SD[i];
         const uint32_t x = make_uint32(xtime14(s), xtime9(s), xtime13(s), xtime11(s));

         TD[i] = x;
         TD[i+256] = rotate_right(x, 8);
         TD[i+512] = rotate_right(x, 16);
         TD[i+768] = rotate_right(x, 24);
      }
      static const std::vector<uint32_t> E = TD;
      return E;
   // };
   // static const std::vector<uint32_t> TD = compute_TD();
   // return TD;
}

/*
* AES Encryption
*/
void aes_encrypt_n(const std::vector<uint32_t>& EK,
                   const std::vector<uint8_t>& ME,
                   const uint8_t in[], uint8_t out[])
{
   const size_t cache_line_size = CACHE_LINE_SIZE;

   const std::vector<uint32_t> TE = AES_TE();

   // Hit every cache line of TE
   uint32_t Z = 0;
   for(size_t i = 0; i < TE.size(); i += cache_line_size / sizeof(uint32_t))
   {
      Z |= TE[i];
   }
   Z &= TE[82]; // this is zero, which hopefully the compiler cannot deduce


      uint32_t T0, T1, T2, T3;
      T0=*((uint32_t *)(in));
      T1=*((uint32_t *)(in + 4));
      T2=*((uint32_t *)(in + 8));
      T3=*((uint32_t *)(in + 12));
     
      T0 ^= EK[0];
      T1 ^= EK[1];
      T2 ^= EK[2];
      T3 ^= EK[3];

      T0 ^= Z;

      /* Use only the first 256 entries of the TE table and do the
      * rotations directly in the code. This reduces the number of
      * cache lines potentially used in the first round from 64 to 16
      * (assuming a typical 64 byte cache line), which makes timing
      * attacks a little harder; the first round is particularly
      * vulnerable.
      */

      uint32_t B0 = TE[get_byte(0, T0)] ^
                  rotate_right(TE[get_byte(1, T1)],  8) ^
                  rotate_right(TE[get_byte(2, T2)], 16) ^
                  rotate_right(TE[get_byte(3, T3)], 24) ^ EK[4];

      uint32_t B1 = TE[get_byte(0, T1)] ^
                  rotate_right(TE[get_byte(1, T2)],  8) ^
                  rotate_right(TE[get_byte(2, T3)], 16) ^
                  rotate_right(TE[get_byte(3, T0)], 24) ^ EK[5];

      uint32_t B2 = TE[get_byte(0, T2)] ^
                  rotate_right(TE[get_byte(1, T3)],  8) ^
                  rotate_right(TE[get_byte(2, T0)], 16) ^
                  rotate_right(TE[get_byte(3, T1)], 24) ^ EK[6];

      uint32_t B3 = TE[get_byte(0, T3)] ^
                  rotate_right(TE[get_byte(1, T0)],  8) ^
                  rotate_right(TE[get_byte(2, T1)], 16) ^
                  rotate_right(TE[get_byte(3, T2)], 24) ^ EK[7];

      #pragma unroll
      for(size_t r = 2*4; r < 40; r += 2*4)
      {
         T0 = EK[r  ] ^ TE[get_byte(0, B0)      ] ^ TE[get_byte(1, B1) + 256] ^
                        TE[get_byte(2, B2) + 512] ^ TE[get_byte(3, B3) + 768];
         T1 = EK[r+1] ^ TE[get_byte(0, B1)      ] ^ TE[get_byte(1, B2) + 256] ^
                        TE[get_byte(2, B3) + 512] ^ TE[get_byte(3, B0) + 768];
         T2 = EK[r+2] ^ TE[get_byte(0, B2)      ] ^ TE[get_byte(1, B3) + 256] ^
                        TE[get_byte(2, B0) + 512] ^ TE[get_byte(3, B1) + 768];
         T3 = EK[r+3] ^ TE[get_byte(0, B3)      ] ^ TE[get_byte(1, B0) + 256] ^
                        TE[get_byte(2, B1) + 512] ^ TE[get_byte(3, B2) + 768];

         B0 = EK[r+4] ^ TE[get_byte(0, T0)      ] ^ TE[get_byte(1, T1) + 256] ^
                        TE[get_byte(2, T2) + 512] ^ TE[get_byte(3, T3) + 768];
         B1 = EK[r+5] ^ TE[get_byte(0, T1)      ] ^ TE[get_byte(1, T2) + 256] ^
                        TE[get_byte(2, T3) + 512] ^ TE[get_byte(3, T0) + 768];
         B2 = EK[r+6] ^ TE[get_byte(0, T2)      ] ^ TE[get_byte(1, T3) + 256] ^
                        TE[get_byte(2, T0) + 512] ^ TE[get_byte(3, T1) + 768];
         B3 = EK[r+7] ^ TE[get_byte(0, T3)      ] ^ TE[get_byte(1, T0) + 256] ^
                        TE[get_byte(2, T1) + 512] ^ TE[get_byte(3, T2) + 768];
      }

      out[ 0] = SE[get_byte(0, B0)] ^ ME[0];
      out[ 1] = SE[get_byte(1, B1)] ^ ME[1];
      out[ 2] = SE[get_byte(2, B2)] ^ ME[2];
      out[ 3] = SE[get_byte(3, B3)] ^ ME[3];
      out[ 4] = SE[get_byte(0, B1)] ^ ME[4];
      out[ 5] = SE[get_byte(1, B2)] ^ ME[5];
      out[ 6] = SE[get_byte(2, B3)] ^ ME[6];
      out[ 7] = SE[get_byte(3, B0)] ^ ME[7];
      out[ 8] = SE[get_byte(0, B2)] ^ ME[8];
      out[ 9] = SE[get_byte(1, B3)] ^ ME[9];
      out[10] = SE[get_byte(2, B0)] ^ ME[10];
      out[11] = SE[get_byte(3, B1)] ^ ME[11];
      out[12] = SE[get_byte(0, B3)] ^ ME[12];
      out[13] = SE[get_byte(1, B0)] ^ ME[13];
      out[14] = SE[get_byte(2, B1)] ^ ME[14];
      out[15] = SE[get_byte(3, B2)] ^ ME[15];
      
}

/*
* AES Decryption
*/
// void aes_decrypt_n(const std::vector<uint32_t>& DK, 
//                    const std::vector<uint8_t>& MD,
//                    const uint8_t in[], uint8_t out[])
// {

//    const size_t cache_line_size = CACHE_LINE_SIZE;
//    const std::vector<uint32_t>& TD = AES_TD();

//    uint32_t Z = 0;
//    for(size_t i = 0; i < TD.size(); i += cache_line_size / sizeof(uint32_t))
//    {
//       Z |= TD[i];
//    }

//    Z &= TD[99]; // this is zero, which hopefully the compiler cannot deduce

//    uint32_t T0 = load_be<uint32_t>(in, 0) ^ DK[0];
//    uint32_t T1 = load_be<uint32_t>(in, 1) ^ DK[1];
//    uint32_t T2 = load_be<uint32_t>(in, 2) ^ DK[2];
//    uint32_t T3 = load_be<uint32_t>(in, 3) ^ DK[3];

//    T0 ^= Z;

//    uint32_t B0 = TD[get_byte(0, T0)] ^
//                rotate_right(TD[get_byte(1, T3)],  8) ^
//                rotate_right(TD[get_byte(2, T2)], 16) ^
//                rotate_right(TD[get_byte(3, T1)], 24) ^ DK[4];

//    uint32_t B1 = TD[get_byte(0, T1)] ^
//                rotate_right(TD[get_byte(1, T0)],  8) ^
//                rotate_right(TD[get_byte(2, T3)], 16) ^
//                rotate_right(TD[get_byte(3, T2)], 24) ^ DK[5];

//    uint32_t B2 = TD[get_byte(0, T2)] ^
//                rotate_right(TD[get_byte(1, T1)],  8) ^
//                rotate_right(TD[get_byte(2, T0)], 16) ^
//                rotate_right(TD[get_byte(3, T3)], 24) ^ DK[6];

//    uint32_t B3 = TD[get_byte(0, T3)] ^
//                rotate_right(TD[get_byte(1, T2)],  8) ^
//                rotate_right(TD[get_byte(2, T1)], 16) ^
//                rotate_right(TD[get_byte(3, T0)], 24) ^ DK[7];

//    for(size_t r = 2*4; r < 40; r += 2*4)
//    {
//       T0 = DK[r  ] ^ TD[get_byte(0, B0)      ] ^ TD[get_byte(1, B3) + 256] ^
//                      TD[get_byte(2, B2) + 512] ^ TD[get_byte(3, B1) + 768];
//       T1 = DK[r+1] ^ TD[get_byte(0, B1)      ] ^ TD[get_byte(1, B0) + 256] ^
//                      TD[get_byte(2, B3) + 512] ^ TD[get_byte(3, B2) + 768];
//       T2 = DK[r+2] ^ TD[get_byte(0, B2)      ] ^ TD[get_byte(1, B1) + 256] ^
//                      TD[get_byte(2, B0) + 512] ^ TD[get_byte(3, B3) + 768];
//       T3 = DK[r+3] ^ TD[get_byte(0, B3)      ] ^ TD[get_byte(1, B2) + 256] ^
//                      TD[get_byte(2, B1) + 512] ^ TD[get_byte(3, B0) + 768];

//       B0 = DK[r+4] ^ TD[get_byte(0, T0)      ] ^ TD[get_byte(1, T3) + 256] ^
//                      TD[get_byte(2, T2) + 512] ^ TD[get_byte(3, T1) + 768];
//       B1 = DK[r+5] ^ TD[get_byte(0, T1)      ] ^ TD[get_byte(1, T0) + 256] ^
//                      TD[get_byte(2, T3) + 512] ^ TD[get_byte(3, T2) + 768];
//       B2 = DK[r+6] ^ TD[get_byte(0, T2)      ] ^ TD[get_byte(1, T1) + 256] ^
//                      TD[get_byte(2, T0) + 512] ^ TD[get_byte(3, T3) + 768];
//       B3 = DK[r+7] ^ TD[get_byte(0, T3)      ] ^ TD[get_byte(1, T2) + 256] ^
//                      TD[get_byte(2, T1) + 512] ^ TD[get_byte(3, T0) + 768];
//    }

//    out[ 0] = SD[get_byte(0, B0)] ^ MD[0];
//    out[ 1] = SD[get_byte(1, B3)] ^ MD[1];
//    out[ 2] = SD[get_byte(2, B2)] ^ MD[2];
//    out[ 3] = SD[get_byte(3, B1)] ^ MD[3];
//    out[ 4] = SD[get_byte(0, B1)] ^ MD[4];
//    out[ 5] = SD[get_byte(1, B0)] ^ MD[5];
//    out[ 6] = SD[get_byte(2, B3)] ^ MD[6];
//    out[ 7] = SD[get_byte(3, B2)] ^ MD[7];
//    out[ 8] = SD[get_byte(0, B2)] ^ MD[8];
//    out[ 9] = SD[get_byte(1, B1)] ^ MD[9];
//    out[10] = SD[get_byte(2, B0)] ^ MD[10];
//    out[11] = SD[get_byte(3, B3)] ^ MD[11];
//    out[12] = SD[get_byte(0, B3)] ^ MD[12];
//    out[13] = SD[get_byte(1, B2)] ^ MD[13];
//    out[14] = SD[get_byte(2, B1)] ^ MD[14];
//    out[15] = SD[get_byte(3, B0)] ^ MD[15];
   
// }

void aes_key_schedule(const uint8_t key[], size_t length,
                      std::vector<uint32_t>& EK,
                      std::vector<uint32_t>& DK,
                      std::vector<uint8_t>& ME,
                      std::vector<uint8_t>& MD)
{
   static const uint32_t RC[10] = {
      0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
      0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000 };

   const size_t rounds = (16 / 4) + 6;
   
   uint32_t XEK[48], XDK[48];
   //std::vector<uint32_t> XEK(length + 32), XDK(length + 32);

   const size_t X = length / 4;
   const std::vector<uint32_t>& TD = AES_TD();
   
   // Make clang-analyzer happy
   // BOTAN_ASSERT(X == 4 || X == 6 || X == 8, "Valid AES key size");

   for(size_t i = 0; i != 4; ++i)
      XEK[i] = load_be<uint32_t>(key, i);

   #pragma unroll
   for(size_t i = 4; i < 4*(10+1); i += 4)
   {
      XEK[i] = XEK[i-4] ^ RC[(i-4)/4] ^
               make_uint32(SE[get_byte(1, XEK[i-1])],
                           SE[get_byte(2, XEK[i-1])],
                           SE[get_byte(3, XEK[i-1])],
                           SE[get_byte(0, XEK[i-1])]);

      #pragma unroll
      for(size_t j = 1; j != 4; ++j)
      {
         XEK[i+j] = XEK[i+j-4];

         // if(X == 8 && j == 4)
         //    XEK[i+j] ^= make_uint32(SE[get_byte(0, XEK[i+j-1])],
         //                            SE[get_byte(1, XEK[i+j-1])],
         //                            SE[get_byte(2, XEK[i+j-1])],
         //                            SE[get_byte(3, XEK[i+j-1])]);
         // else
            XEK[i+j] ^= XEK[i+j-1];
      }
   }


   #pragma unroll
   for(size_t i = 0; i != 4*(10+1); i += 4)
   {
      XDK[i  ] = XEK[4*10-i  ];
      XDK[i+1] = XEK[4*10-i+1];
      XDK[i+2] = XEK[4*10-i+2];
      XDK[i+3] = XEK[4*10-i+3];
   }

   #pragma unroll
   for(size_t i = 4; i != 16 + 24; ++i)
      XDK[i] = TD[SE[get_byte(0, XDK[i])] +   0] ^
               TD[SE[get_byte(1, XDK[i])] + 256] ^
               TD[SE[get_byte(2, XDK[i])] + 512] ^
               TD[SE[get_byte(3, XDK[i])] + 768];

   ME.resize(16);
   MD.resize(16);

   for(size_t i = 0; i != 4; ++i)
   {
      store_be(XEK[i+4*10], &ME[4*i]);
      store_be(XEK[i], &MD[4*i]);
   }

   EK.resize(40);
   DK.resize(40);
  
   std::memmove(EK.data(), XEK, sizeof(uint32_t)*EK.size());
   std::memmove(DK.data(), XDK, sizeof(uint32_t)*DK.size());
}



static uint8_t in_key[24] = {34, 10, 241, 249, 171, 217, 15, 66, 89, 228, 19, 119, 153, 254, 166, 4, 221, 15, 231, 121, 114, 240, 65, 17};
static uint8_t in[64] = {0x00};
static uint8_t out[64] = {0};

int main(int argc, char *argv[])
{
   read(0, in_key, 24);
   read(0, in, 64);
   std::vector<uint32_t> m_EK, m_DK;
   std::vector<uint8_t> m_ME, m_MD;
   aes_key_schedule(in_key, 16, m_EK, m_DK, m_ME, m_MD);
   aes_encrypt_n(m_EK, m_ME, in, out);
	write(1, m_EK.data(), 40*4);
	write(1, m_DK.data(), 40*4);
   write(1, out, 64);
   return 0;
}
