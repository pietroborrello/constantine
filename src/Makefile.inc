V?=0
ifneq ($V,0)
QUIET=
ECHO:=@\#
QMAKE=VERBOSE=1 make
else
QUIET= @
ECHO= echo
QMAKE=make -s
endif
