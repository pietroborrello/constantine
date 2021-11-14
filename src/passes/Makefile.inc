include $(ROOT)/Makefile.inc

ARCH ?= native

LLVMPREFIX=$(shell readlink -f $(ROOT)/llvm-*/bin)
LLVMINC=$(LLVMPREFIX)/include
LLVMLIB=$(LLVMPREFIX)/lib

CXX=$(LLVMPREFIX)/bin/clang++
INSTALL_DIR=$(ROOT)/bin

CFLAGS  += $(CXXFLAGS) -fPIC -Wno-long-long -Wall -W -Wno-unused-parameter -Wwrite-strings -Wno-unknown-warning-option -DHAVE_EXCEPTIONS=0 -march=$(ARCH)
CFLAGS  += $(shell $(LLVMPREFIX)/bin/llvm-config --cxxflags) -g
LDFLAGS += $(shell $(LLVMPREFIX)/bin/llvm-config --ldflags) -L$(LLVMLIB)

PASSLIBNAME =$(PASSNAME).so

HEADERS += $(wildcard ../include/common/*.h) $(wildcard ../include/$(PASSNAME)/*.h)

INCLUDES += -I../include/common -I../include/$(PASSNAME)

all: $(PASSLIBNAME)

$(PASSLIBNAME): $(OBJS)
	$(QUIET) $(ECHO) "  [LINK] $@"
	$(QUIET) $(CXX) $(CFLAGS) -shared -o $@ $(CPPS) $(OBJS) $(LDFLAGS) $(LIBS)

%.o: %.cpp $(HEADERS)
	$(QUIET) $(ECHO)  "  [C++] $<"
	$(QUIET) $(CXX) $(CFLAGS) $(INCLUDES) -c -o $@ $<

install: $(INSTALL_DIR)/$(PASSLIBNAME)

$(INSTALL_DIR)/$(PASSLIBNAME): $(PASSLIBNAME)
	$(QUIET) $(ECHO) "  [INSTALL] $< -> $@"
	$(QUIET) install -c -D -m 744 $? $@

clean:
	$(QUIET) $(ECHO) "  [RM] $(OBJS) $(PASSLIBNAME)"
	$(QUIET) rm -f $(OBJS) $(PASSLIBNAME) $(INSTALL_DIR)/$(PASSLIBNAME)
