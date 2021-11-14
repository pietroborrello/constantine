#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <x86intrin.h>
#include <assert.h>
#include <immintrin.h>
#include <string.h>

#include <dfl.h>

#if defined(__AVX512F__)
#define GEN_SIGS(type) \
type type ## _avx2_gather_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size); \
type type ## _avx2_linear_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size); \
type type ## _avx512_linear_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size); \
type type ## _avx512_gather_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size); \
type type ## _dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size); \
void type ## _avx_scatter_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value); \
void type ## _avx512_scatter_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value); \
void type ## _avx2_linear_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value); \
void type ## _avx512_linear_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value); \
void type ## _dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value);
#else
#define GEN_SIGS(type) \
type type ## _avx2_gather_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size); \
type type ## _avx2_linear_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size); \
type type ## _avx512_linear_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size){} \
type type ## _avx512_gather_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size){} \
type type ## _dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size); \
void type ## _avx_scatter_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value); \
void type ## _avx512_scatter_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value){} \
void type ## _avx2_linear_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value); \
void type ## _avx512_linear_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value){} \
void type ## _dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value);
#endif

#define GEN_IMPLS(type) \
type TYPE_avx2_gather_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {return type ## _avx2_gather_dfl_glob_load(obj, ptr, field_off, field_size);} \ 
type TYPE_avx2_linear_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {return type ## _avx2_linear_dfl_glob_load(obj, ptr, field_off, field_size);}; \
type TYPE_avx512_linear_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {return type ## _avx512_linear_dfl_glob_load(obj, ptr, field_off, field_size);}; \
type TYPE_avx512_gather_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {return type ## _avx512_gather_dfl_glob_load(obj, ptr, field_off, field_size);}; \
type TYPE_dfl_glob_load(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size) {return type ## _dfl_glob_load(obj, ptr, field_off, field_size);}; \
void TYPE_avx_scatter_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value) {type ## _avx_scatter_dfl_glob_store(obj, ptr, field_off, field_size, value);}; \
void TYPE_avx512_scatter_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value) {type ## _avx512_scatter_dfl_glob_store(obj, ptr, field_off, field_size, value);}; \
void TYPE_avx2_linear_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value) {type ## _avx2_linear_dfl_glob_store(obj, ptr, field_off, field_size, value);}; \
void TYPE_avx512_linear_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value) {type ## _avx512_linear_dfl_glob_store(obj, ptr, field_off, field_size, value);}; \
void TYPE_dfl_glob_store(unsigned char* obj, unsigned char* ptr, unsigned long field_off, unsigned long field_size, type value) {type ## _dfl_glob_store(obj, ptr, field_off, field_size, value);}; \

#define xstr(s) str(s)
#define str(s) #s
#define GEN_CALL(type, call) str(type) ## str(call)

#define TYPE uint8_t
#define MASK 0xffuL
GEN_SIGS(uint8_t)
GEN_IMPLS(uint8_t)

#define MAX_SIZE 4096

TYPE arr[MAX_SIZE*2] __attribute__ (( __aligned__(MAX_SIZE*2) ));

#if defined(__AVX512F__)
void print512_num(__m512i var)
{
    uint64_t val[8];
    memcpy(val, &var, sizeof(val));
    printf("Numerical: %lx %lx %lx %lx %lx %lx %lx %lx \n", 
           val[0], val[1], val[2], val[3], val[4], val[5], 
           val[6], val[7]);
}
#endif

#define USE_RDTSCP 1
uint64_t rdtsc() {
  uint64_t a, d;
  asm volatile("mfence");
#if USE_RDTSCP
  asm volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");
#else
  asm volatile("rdtsc" : "=a"(a), "=d"(d));
#endif
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

void print256_num(__m256i var)
{
    uint64_t val[4];
    memcpy(val, &var, sizeof(val));
    printf("Numerical: %lx %lx %lx %lx \n", 
           val[0], val[1], val[2], val[3]);
}

#define ITS 1000
int main(int argc, char* argv[]) {
    printf("START DFL TESTS - DFL_STRIDE: %d\n", 64);
    unsigned int p;

    unsigned long sum0=0, sum1=0, sum2=0, sum3=0, sum4=0, sum5=0, sum6=0;
    for(int SIZE = 1024; SIZE <= 4096; SIZE += 512) {
        printf("SIZE: %d\n", SIZE * sizeof(TYPE));
        for(int it = 0; it < ITS; ++it) for (int i = 0; i < SIZE; ++i) {
            arr[i] = i;
        }
        // READ tests
        {
            unsigned long elaps0=0, elaps1=0, elaps2=0, elaps3=0, elaps4=0, elaps5=0, elaps6=0;
            {
                unsigned long t1 = rdtsc(&p);
                for(int it = 0; it < ITS; ++it) for (int i = 0; i < SIZE; ++i) {
                    sum0 += *((volatile TYPE *)arr + i);
                } 
                unsigned long t2 = rdtsc(&p);

                printf("  elapsed0: %lu\n", ((t2 - t1))/ITS);
                elaps0 = ((t2 - t1))/ITS;
            }

            {
                unsigned long t1 = rdtsc(&p);
                for(int it = 0; it < ITS; ++it) for (int i = 0; i < SIZE; ++i) {
                    sum1 += TYPE_dfl_glob_load(arr, arr+i, 0, SIZE * sizeof(TYPE));
                } 
                unsigned long t2 = rdtsc(&p);

                elaps1 = ((t2 - t1))/ITS;
            }

            {
                unsigned long t1 = rdtsc(&p);
                for(int it = 0; it < ITS; ++it) for (int i = 0; i < SIZE; ++i) {
                    sum2 += TYPE_avx2_gather_dfl_glob_load(arr, arr+i, 0, SIZE * sizeof(TYPE));
                } 
                unsigned long t2 = rdtsc(&p);

                elaps2 = ((t2 - t1))/ITS;
            }

            {
                unsigned long t1 = rdtsc(&p);
                for(int it = 0; it < ITS; ++it) for (int i = 0; i < SIZE; ++i) {
                    sum3 += TYPE_avx2_linear_dfl_glob_load(arr, arr+i, 0, SIZE * sizeof(TYPE));
                } 
                unsigned long t2 = rdtsc(&p);

                elaps3 = ((t2 - t1))/ITS;
            }

#if defined(__AVX512F__)
            {
                unsigned long t1 = rdtsc(&p);
                for(int it = 0; it < ITS; ++it) for (int i = 0; i < SIZE; ++i) {
                    sum4 += TYPE_avx512_linear_dfl_glob_load(arr, arr+i, 0, SIZE * sizeof(TYPE));
                } 
                unsigned long t2 = rdtsc(&p);

                elaps4 = ((t2 - t1))/ITS;
            }

            {
                unsigned long t1 = rdtsc(&p);
                for(int it = 0; it < ITS; ++it) for (int i = 0; i < SIZE; ++i) {
                    sum5 += TYPE_avx512_gather_dfl_glob_load(arr, arr+i, 0, SIZE * sizeof(TYPE));
                } 
                unsigned long t2 = rdtsc(&p);

                elaps5 = ((t2 - t1))/ITS;
            }
#endif
            printf(" R plain     : %lu (%.02f)\n", elaps1, ((float)elaps1)/elaps0);
            printf(" R avx2   gat: %lu (%.02f)\n", elaps2, ((float)elaps2)/elaps0);
            printf(" R avx512 gat: %lu (%.02f)\n", elaps5, ((float)elaps5)/elaps0);
            printf(" R avx2   lin: %lu (%.02f)\n", elaps3, ((float)elaps3)/elaps0);
            printf(" R avx512 lin: %lu (%.02f)\n", elaps4, ((float)elaps4)/elaps0);
            printf("sum: %lu %lu %lu %lu %lu %lu\n", sum0, sum1, sum2, sum3, sum4, sum5);
        }

        // WRITE tests
        {
            unsigned long elaps0=0, elaps1=0, elaps2=0, elaps3=0, elaps4=0, elaps5=0, elaps6=0;
            {
                unsigned long t1 = rdtsc(&p);
                for(int it = 0; it < ITS; ++it) for (int i = 0; i < SIZE; ++i) {
                    *((volatile TYPE *)arr + i) = i;
                } 
                unsigned long t2 = rdtsc(&p);

                printf("  elapsed0: %lu\n", ((t2 - t1))/ITS);
                elaps0 = ((t2 - t1))/ITS;
            }
            for (int i = 0; i < SIZE; ++i) {
                if(arr[i] != (i & MASK)) {
                    printf("Failed: arr[%d] = %lx, %lx\n", i, arr[i], i);
                    assert(0);
                }
                arr[i] = 0xff;
            }

            {
                unsigned long t1 = rdtsc(&p);
                for(int it = 0; it < ITS; ++it) for (int i = 0; i < SIZE; ++i) {
                    TYPE_dfl_glob_store(arr, arr+i, 0, SIZE * sizeof(TYPE), i);
                } 
                unsigned long t2 = rdtsc(&p);

                elaps1 = ((t2 - t1))/ITS;
            }
            for (int i = 0; i < SIZE; ++i) {
                assert(arr[i] == (i & MASK));
                arr[i] = 0xff;
            }

#if defined(__AVX512F__)
            {
                unsigned long t1 = rdtsc(&p);
                for(int it = 0; it < ITS; ++it) for (int i = 0; i < SIZE; ++i) {
                    TYPE_avx512_linear_dfl_glob_store(arr, arr+i, 0, SIZE * sizeof(TYPE), i);
                } 
                unsigned long t2 = rdtsc(&p);

                elaps4 = ((t2 - t1))/ITS;
            }
            for (int i = 0; i < SIZE; ++i) {
                if(arr[i] != (i & MASK)) {
                    printf("Failed: arr[%d] = %lx, %lx\n", i, arr[i], i);
                    assert(0);
                }
                arr[i] = 0xff;
            }
#endif

            {
                unsigned long t1 = rdtsc(&p);
                for(int it = 0; it < ITS; ++it) for (int i = 0; i < SIZE; ++i) {
                    TYPE_avx2_linear_dfl_glob_store(arr, arr+i, 0, SIZE * sizeof(TYPE), i);
                } 
                unsigned long t2 = rdtsc(&p);

                elaps3 = ((t2 - t1))/ITS;
            }
            for (int i = 0; i < SIZE; ++i) {
                assert(arr[i] == (i & MASK));
                arr[i] = 0xff;
            }

#if defined(__AVX512F__)
            {
                unsigned long t1 = rdtsc(&p);
                for(int it = 0; it < ITS; ++it) for (int i = 0; i < SIZE; ++i) {
                    TYPE_avx_scatter_dfl_glob_store(arr, arr+i, 0, SIZE * sizeof(TYPE), i);
                } 
                unsigned long t2 = rdtsc(&p);

                elaps5 = ((t2 - t1))/ITS;
            }
            for (int i = 0; i < SIZE; ++i) {
                assert(arr[i] == (i & MASK));
                arr[i] = 0xff;
            }
            {
                unsigned long t1 = rdtsc(&p);
                for(int it = 0; it < ITS; ++it) for (int i = 0; i < SIZE; ++i) {
                    TYPE_avx512_scatter_dfl_glob_store(arr, arr+i, 0, SIZE * sizeof(TYPE), i);
                } 
                unsigned long t2 = rdtsc(&p);

                elaps6 = ((t2 - t1))/ITS;
            }
            for (int i = 0; i < SIZE; ++i) {
                if(arr[i] != (i & MASK)) {
                    printf("Failed: arr[%d] = %lx, %lx\n", i, arr[i], i);
                    assert(0);
                }
                arr[i] = 0xff;
            }
#endif
            printf(" W plain     : %lu (%.02f)\n", elaps1, ((float)elaps1)/elaps0);
            printf(" W avx2   sca: %lu (%.02f)\n", elaps5, ((float)elaps5)/elaps0);
            printf(" W avx512 sca: %lu (%.02f)\n", elaps6, ((float)elaps6)/elaps0);
            printf(" W avx2   lin: %lu (%.02f)\n", elaps3, ((float)elaps3)/elaps0);
            printf(" W avx512 lin: %lu (%.02f)\n", elaps4, ((float)elaps4)/elaps0);
        }

    }
    printf("sum: %lu %lu %lu %lu %lu %lu\n", sum0, sum1, sum2, sum3, sum4, sum5);
#if defined(__AVX512F__)
    // check that the program will not segfault due to OOB unmasked reads
    __mmask8 mask   = _cvtu32_mask8((unsigned int) 0);
    __m512i res = _mm512_setzero_si512();
    unsigned long DFL_STRIDE = 4096;
    __m512i index = _mm512_setr_epi64(0*DFL_STRIDE, 1*DFL_STRIDE, 2*DFL_STRIDE, 3*DFL_STRIDE,
                                      4*DFL_STRIDE, 5*DFL_STRIDE, 6*DFL_STRIDE, 7*DFL_STRIDE);
    res =  _mm512_mask_i64gather_epi64(res, mask, index, arr, 1);
    print512_num(res);
#endif

    return 0;
}