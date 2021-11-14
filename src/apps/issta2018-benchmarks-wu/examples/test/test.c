#include <unistd.h>
#include <stdint.h>

uint32_t dough[32] = {0};
static void cookey(register uint32_t *raw1)
{
    register uint32_t *cook, *raw0;
    register int i;
    cook = dough;
    if (*raw1) {
        exit(1);
    } else {
        for( i = 0; i < 16; i++, raw1++ ) {
            raw0 = raw1++;
            *cook = (*raw0 & 0x00fc0000L) << 6;
            *cook |= (*raw0 & 0x00000fc0L) << 10;
            *cook |= (*raw1 & 0x00fc0000L) >> 10;
            *cook++ |= (*raw1 & 0x00000fc0L) >> 6;
            *cook = (*raw0 & 0x0003f000L) << 12;
            *cook |= (*raw0 & 0x0000003fL) << 16;
            *cook |= (*raw1 & 0x0003f000L) >> 4;
            *cook++ |= (*raw1 & 0x0000003fL);
        }
    }
    return;
}

int main(int argc, char* argv[0]) {
    uint32_t kn[32] = {0};
    read(0, &kn, 4 * 32);
    cookey(kn);
    write(1, &dough, 4 * 32);
}