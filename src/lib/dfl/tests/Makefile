ROOT=../../..
MODULE = test
SRCS = test.c

OBJS= $(SRCS:%.c=%.o)
ARCH ?= native
include $(ROOT)/Makefile.inc

MODULE_NAME=test.bcc

LLVMPREFIX=$(shell readlink -f $(ROOT)/llvm-*/bin)
CC=$(LLVMPREFIX)/bin/clang
CFLAGS += $(CXXFLAGS) -Wall -Wno-long-long -flto -fPIC -O3 -march=$(ARCH)
LDFLAGS += -fuse-ld=lld -Wl,-save-temps
LOPT_FLAGS += -O3 -march=$(ARCH)
INCLUDES += -I$(ROOT)/lib/include/dfl
INSTALL_DIR=$(ROOT)/bin
HEADERS = $(wildcard $(ROOT)/lib/include/dfl/*.h)

ifeq ($(USE_SECTIONIFY),YES)
LOPT_FLAGS+=-load=$(LLVMSECTIONIFY_SO) -sectionify -sectionify-no-override -sectionify-data-section-map=$(SECTIONIFY_DATA_SECTION_MAP) -sectionify-function-section-map=$(SECTIONIFY_FUNCTION_SECTION_MAP)
endif

$(MODULE_NAME): $(OBJS) $(HEADERS) $(COMMON_BCCS)
	cd ../../../ && . ./setup.sh
	cd ../../ && make clean install
	$(QUIET) $(ECHO) "  [LINK] $@.o"
	$(QUIET) $(CC) $(CFLAGS) $(LDFLAGS) -o $(MODULE) $(OBJS) ../dfl.bcc -Wall $(COMMON_BCCS)

all: $(MODULE_NAME)

run: all
	taskset -c 3 ./$(MODULE)

send: all
	scp ./$(MODULE) vu:/home/pietroborrello/tests/$(MODULE)

%.o: %.c $(HEADERS)
	$(QUIET) $(ECHO) "  [CC] $<"
	$(QUIET) $(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

clean: $(EXTRA_CLEAN)
	$(QUIET) $(ECHO) "  [RM] *.BCC *.bcc *.bc *.BCL *.BCL.sh *.bcl *.txt $(OBJS) *.s $(COMMON_BCCS)"
	$(QUIET) rm -f *.BCC *.bcc *.bc *.BCL *.BCL.sh *.bcl *.txt *.o $(OBJS) *.s $(COMMON_BCCS)

distclean: clean
	$(QUIET) $(ECHO) "  [RM] $(INSTALL_DIR)/$(MODULE_NAME)"
	$(QUIET) rm -f $(INSTALL_DIR)/$(MODULE_NAME)
