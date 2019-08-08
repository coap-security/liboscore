CPPFLAGS += -I../src/include/
CFLAGS += -Wall -Werror -Wpedantic -std=c11
CFLAGS += -g3 -O0
CFLAGS += -MD

CFLAGS += -fsanitize=undefined -fsanitize=address
LDFLAGS += -fsanitize=undefined -fsanitize=address

include Makefile.mockoap
include Makefile.libcose

all: test

test: cryptobackend-aead standalone-demo
	set -ex; for x in $^; do ./$$x; done

include $(wildcard *.d)

standalone-demo: standalone-demo.o ${BACKEND_OBJS}

cryptobackend-aead: cryptobackend-aead.o ${BACKEND_OBJS}

clean:
	rm -f standalone-demo
	rm -f cryptobackend-aead
	rm -f *.o
	rm -f *.d

# recommended GNU Make rule for building dependency files
%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -M $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$


.PHONY: test clean
