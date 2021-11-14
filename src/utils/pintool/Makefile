PIN_ROOT := $(HOME)/pin314

# Pin's default config
CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config
include $(PIN_ROOT)/source/tools/SimpleExamples/makefile.rules
include $(TOOLS_ROOT)/Config/makefile.default.rules

# custom pintool begins here
fast-profiler: localdirs obj-intel64/memory-fast.so
profiler: localdirs obj-intel64/memory.so
check-profiler: localdirs obj-intel64/memory-check.so

fast-profiler-test: fast-profiler
	$(PIN_ROOT)/pin -t obj-intel64/memory-fast.so -o ls_trace.out -- ls

check-profiler-test: check-profiler
	$(PIN_ROOT)/pin -t obj-intel64/memory-check.so -o ls_trace.out -- ls

profiler-test: profiler
	$(PIN_ROOT)/pin -t obj-intel64/memory.so -o ls_trace.out -- ls

localdirs:
	mkdir -p obj-intel64

.PHONY: localdirs
.PHONY: profiler
.PHONY: profiler-test
.PHONY: check-profiler-test