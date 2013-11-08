MAKEFLAGS 	:= -r -R --no-print-directory

ifeq ($(strip $(V)),)
	E = @echo
	Q = @
else
	E = @\#
	Q =
endif

FIND		:= find
CSCOPE		:= cscope
TAGS		:= ctags
RM		:= rm -f
LD		:= ld
CC		:= gcc
ECHO		:= echo
NM		:= nm
AWK		:= awk
SH		:= bash
MAKE		:= make
OBJCOPY		:= objcopy

#
# Fetch ARCH from the uname if not yet set
#
ARCH ?= $(shell uname -m | sed		\
		-e s/i.86/i386/		\
		-e s/sun4u/sparc64/	\
		-e s/arm.*/arm/		\
		-e s/sa110/arm/		\
		-e s/s390x/s390/	\
		-e s/parisc64/parisc/	\
		-e s/ppc.*/powerpc/	\
		-e s/mips.*/mips/	\
		-e s/sh[234].*/sh/)

ifeq ($(ARCH),x86_64)
	ARCH         := x86
	DEFINES      := -DCONFIG_X86_64
	LDARCH       := i386:x86-64
endif

ifneq ($(ARCH),x86)
$(error "The architecture $(ARCH) isn't supported"))
endif

cflags-y	+= -iquote src/include -iquote src/
cflags-y	+= -fno-strict-aliasing
export cflags-y

VERSION_MAJOR		:= 0
VERSION_MINOR		:= 1
VERSION_SUBLEVEL	:=
VERSION_EXTRA		:=
VERSION_NAME		:=

export VERSION_MAJOR VERSION_MINOR VERSION_SUBLEVEL VERSION_EXTRA VERSION_NAME

include scripts/Makefile.version
include scripts/Makefile.config

LIBS		:= -lrt -lpthread -lprotobuf-c

DEFINES		+= -D_FILE_OFFSET_BITS=64
DEFINES		+= -D_GNU_SOURCE

WARNINGS	:= -Wall

ifneq ($(WERROR),0)
	WARNINGS += -Werror
endif

ifeq ($(DEBUG),1)
	DEFINES += -DCR_DEBUG
	CFLAGS	+= -O0 -ggdb3
else
	CFLAGS	+= -O2
endif

CFLAGS		+= $(WARNINGS) $(DEFINES)

export E Q CC ECHO MAKE CFLAGS LIBS ARCH DEFINES MAKEFLAGS
export SH RM OBJCOPY LDARCH LD

include scripts/Makefile.rules

build := -r -R --no-print-directory -f scripts/Makefile.build makefile=Makefile obj

PROGRAM		:= cpt2

.PHONY: all clean tags protobuf

src/protobuf/%:
	$(Q) $(MAKE) $(build)=src/protobuf $@
src/protobuf/built-in.o:
	$(Q) $(MAKE) $(build)=src/protobuf $@
protobuf: src/protobuf/built-in.o

src/res/%:
	$(Q) $(MAKE) $(build)=src/res $@
src/res/built-in.o:
	$(Q) $(MAKE) $(build)=src/res $@

src/%: $(VERSION_HEADER) protobuf config src/res/built-in.o
	$(Q) $(MAKE) $(build)=src $@
src/built-in.o: src $(VERSION_HEADER) protobuf config src/res/built-in.o
	$(Q) $(MAKE) $(build)=src all

$(PROGRAM): src/built-in.o src/res/built-in.o src/protobuf/built-in.o
	$(E) "  LINK    " $@
	$(Q) $(CC) $(CFLAGS) $^ $(LIBS) -o $@

all: $(PROGRAM)

docs:
	$(Q) $(MAKE) -s -C Documentation all

tags:
	$(E) "  GEN     " $@
	$(Q) $(RM) tags
	$(Q) $(FIND) -L . -name '*.[hcS]' ! -path './.*' -print | xargs ctags -a

clean:
	$(E) "  CLEAN"
	$(Q) $(MAKE) $(build)=src clean
	$(Q) $(MAKE) $(build)=src/res clean
	$(Q) $(MAKE) $(build)=src/protobuf clean
	$(Q) $(MAKE) -s -C Documentation clean
	$(Q) $(RM) $(PROGRAM)
	$(Q) $(RM) $(CONFIG)

.DEFAULT_GOAL := all
