include ../cases/Makefile.include

OPTFLAGS ?= -O0

CPPFLAGS += -I../../src/include/
CPPFLAGS += -Ilibconfigs/
CFLAGS += -Werror -std=c11
BE_PEDANTIC ?= yes
ifeq (yes,${BE_PEDANTIC})
    CFLAGS += -Wall -Wpedantic
endif
CFLAGS += -g3
CFLAGS += -MD
CFLAGS += ${OPTFLAGS}

CFLAGS += -fsanitize=undefined -fsanitize=address
LDFLAGS += -fsanitize=undefined -fsanitize=address

all: test

vpath %.c ../../src/
vpath %.c ../cases/

ifeq (libs,$(wildcard libs))
include Makefile.mockoap
include Makefile.libcose
else
# We might pull in libs through a dependency of the to-be-included
# Makefile.libcose, but even some expansions run into errors
$(warning "Before running anything else, run `make libs` to ensure all Makefile components are ready")
endif
include Makefile.rustaead

BACKEND_OBJS += testwrapper.c

test: ${CASES}
	set -ex; for x in $^; do ./$$x; done

test-all-versions:
	${MAKE} clean
	${MAKE} CC=gcc OPTFLAGS=-O0 TESTS_USE_TINYDTLS=no test
	${MAKE} clean
	${MAKE} CC=gcc OPTFLAGS=-O3 TESTS_USE_TINYDTLS=no test
	${MAKE} clean
	${MAKE} CC=clang TESTS_USE_TINYDTLS=no test
	${MAKE} clean
	# only relevant with TINYDTLS
# 	${MAKE} CC=clang BE_PEDANTIC=no test
# 	${MAKE} clean

include $(wildcard *.d)

standalone-demo: standalone-demo.o ${BACKEND_OBJS}

cryptobackend-aead: cryptobackend-aead.o ${BACKEND_OBJS}

unprotect-demo: unprotect-demo.o contextpair.o protection.o oscore_message.o ${BACKEND_OBJS}

unit-contextpair-window: unit-contextpair-window.o contextpair.o ${BACKEND_OBJS}

cryptobackend-hkdf: cryptobackend-hkdf.o ${BACKEND_OBJS}

libs:
	mkdir libs
	# not created as submodules as those are expected to be used in full
	# library fashion on the long run
	# temporarily switching over to upstream version while vendor version has not merged upstream code
	#cd libs && git clone https://github.com/chrysn-pull-requests/libcose -b liboscore-vendor
	cd libs && git clone https://github.com/bergzand/libcose
	cd libs && git clone https://github.com/bergzand/NanoCBOR nanocbor
	cd libs && git clone https://github.com/eclipse/tinydtls -b develop
	cd libs && git clone https://github.com/intel/tinycrypt

libs/tinycrypt/lib/libtinycrypt.a:
	$(MAKE) -C libs/tinycrypt/lib

clean:
	rm -f ${CASES}
	rm -f *.o
	rm -f *.d

	# Not cleaning libs: there may be user edits in them.

distclean: clean
	rm -rf libs

# recommended GNU Make rule for building dependency files
%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -M $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$


.PHONY: test clean distclean
