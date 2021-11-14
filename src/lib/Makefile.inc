include $(ROOT)/Makefile.inc

MODULE_NAME=$(MODULE).bcc

ARCH ?= native
OPT ?= -O3

LLVMPREFIX=$(shell readlink -f $(LLVM_SRC)/bin)
CC=$(LLVMPREFIX)/bin/clang
CFLAGS += $(CXXFLAGS) -Wall -Wno-long-long -flto -fPIC $(OPT) -march=$(ARCH)
LDFLAGS += -fuse-ld=lld -Wl,-save-temps
LOPT_FLAGS += $(OPT) -march=$(ARCH)
INCLUDES += -I$(ROOT)/lib/include/$(MODULE)
INSTALL_DIR=$(ROOT)/bin
HEADERS = $(wildcard $(ROOT)/lib/include/$(MODULE)/*.h)

ifeq ($(USE_SECTIONIFY),YES)
LOPT_FLAGS+=-load=$(LLVMSECTIONIFY_SO) -sectionify -sectionify-no-override -sectionify-data-section-map=$(SECTIONIFY_DATA_SECTION_MAP) -sectionify-function-section-map=$(SECTIONIFY_FUNCTION_SECTION_MAP)
endif

$(MODULE_NAME): $(OBJS) $(HEADERS) $(COMMON_BCCS)
	$(QUIET) $(ECHO) "  [LINK] $@.o"
	$(QUIET) $(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@.o $(OBJS) $(COMMON_BCCS)
	$(QUIET) $(ECHO) "  [OPT] $@"
	$(QUIET) $(LLVMPREFIX)/bin/opt $(LOPT_FLAGS) -o $@ $@.o.0.5.precodegen.bc

all: $(MODULE_NAME)

%.o: %.c $(HEADERS)
	$(QUIET) $(ECHO) "  [CC] $<"
	$(QUIET) $(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

install: $(INSTALL_DIR)/$(MODULE_NAME)

$(INSTALL_DIR)/$(MODULE_NAME): $(MODULE_NAME)
	install -c -D -m 744 $? $@

clean: $(EXTRA_CLEAN)
	$(QUIET) $(ECHO) "  [RM] *.BCC *.bcc *.bc *.BCL *.BCL.sh *.bcl *.txt $(OBJS) *.s $(COMMON_BCCS)"
	$(QUIET) rm -f *.BCC *.bcc *.bc *.BCL *.BCL.sh *.bcl *.txt *.o $(OBJS) *.s $(COMMON_BCCS)

distclean: clean
	$(QUIET) $(ECHO) "  [RM] $(INSTALL_DIR)/$(MODULE_NAME)"
	$(QUIET) rm -f $(INSTALL_DIR)/$(MODULE_NAME)
