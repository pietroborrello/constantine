ROOT=../..

MODULE = utils
SRCS = utils.c

OBJS= $(SRCS:%.c=%.o)

CFLAGS += -fno-builtin -fno-vectorize -ffreestanding
LOPT_FLAGS += -disable-simplify-libcalls
OPT = -O1

include $(ROOT)/lib/Makefile.inc
