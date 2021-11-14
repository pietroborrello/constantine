ROOT=../..

MODULE = dft
SRCS = dft.c hook.c

OBJS= $(SRCS:%.c=%.o)
FLAGS = -fPIC -O3 -DDFT_WRAP_SOURCES -DDFT_VERBOSE
CFLAGS += $(FLAGS)
BCFLAGS += $(FLAGS) -fsanitize=dataflow

include $(ROOT)/lib/Makefile.inc

dft.o: dft.c $(HEADERS)
	$(QUIET) $(ECHO) "  [CC] $<"
	$(QUIET) $(CC) $(BCFLAGS) $(INCLUDES) -c -o $@ $<
