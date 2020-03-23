MODULE = oscore

# See comment in MAkefile.include
OSCOREBASE := $(abspath $(lastword $(MAKEFILE_LIST))/../../..)

vpath %.c ${OSCOREBASE}/src
vpath %.c ${OSCOREBASE}/backends/nanocoap/src/
vpath %.c ${OSCOREBASE}/backends/libcose/src/

SRC += oscore_message.c
SRC += context_b1.c
SRC += contextpair.c
SRC += oscore_msg_native.c
SRC += oscore_test.c
SRC += protection.c

SRC += libcose.c

include $(RIOTBASE)/Makefile.base
