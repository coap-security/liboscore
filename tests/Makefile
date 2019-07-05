CPPFLAGS += -I../src/include/
CFLAGS += -Wall -Werror -Wpedantic -std=c11
CFLAGS += -MD

include Makefile.mockoap

all: test

test: standalone-demo
	./$<

include $(wildcard *.d)

standalone-demo: standalone-demo.o ${BACKEND_OBJS}

clean:
	rm -f standalone-demo
	rm -f *.o
	rm -f *.d

# recommended GNU Make rule for building dependency files
%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -M $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$


.PHONY: test clean
