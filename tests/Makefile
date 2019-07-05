CPPFLAGS += -I../src/include/
CFLAGS += -Wall -Werror -Wpedantic -std=c11

include Makefile.mockoap

all: test

test: standalone-demo
	./$<

standalone-demo: standalone-demo.o ${BACKEND_OBJS}

clean:
	rm -f standalone-demo
	rm -f *.o

.PHONY: test clean
