SVF_HOME=$(ROOT)/SVF
SVF_HEADER=$(SVF_HOME)/include
SVF_LIB=$(SVF_HOME)/Debug-build/lib

LDFLAGS += $(SVF_LIB)/libSvf.a $(SVF_LIB)/CUDD/libCudd.a
CFLAGS += -fno-rtti -Wno-overloaded-virtual -Wno-ignored-qualifiers -Wno-reorder
INCLUDES += -I $(SVF_HEADER)
