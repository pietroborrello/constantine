#include <unistd.h>

#define CAT(x,y) x##y

#define HIGH_INPUT(size, buf) read(STDIN_FILENO, buf, size)
#define LOW_INPUT(size, buf) read(STDIN_FILENO, buf, size)
