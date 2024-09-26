USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
USEMODULE += gnrc_ipv6_default
USEMODULE += gnrc_icmpv6_echo
USEMODULE += gcoap

USEMODULE += shell
USEMODULE += shell_cmds_default
USEMODULE += ps

CFLAGS += -DOSCORE_NANOCOAP_MEMMOVE_MODE

BOARD ?= native

ifneq ($(BOARD),native)
FEATURES_REQUIRED += periph_flashpage
USEMODULE += periph_flashpage_pagewise
endif

ifeq ($(BOARD),particle-xenon)
# When using the MONOFIRMWARE upload process as described in the documentation,
# don't checksum the whole program, that'd render the whole program unbootable
# once data is persisted
CFLAGS += -DPARTICLE_MONOFIRMWARE_CHECKSUMLIMIT

USEMODULE += auto_init_usbus
USEMODULE += stdio_cdc_acm
USEMODULE += usbus_cdc_ecm
GNRC_NETIF_NUMOF = 2
CFLAGS += -DGNRC_IPV6_NIB_CONF_SLAAC -DGNRC_IPV6_NIB_CONF_ARSM
# Allow full-length lines even over CDC-ACM
CFLAGS += -DUSBUS_CDC_ACM_STDIO_BUF_SIZE=512
endif

ifeq ($(BOARD),iotlab-m3)
# for IoT lab
GNRC_NETIF_NUMOF := 2
USEMODULE += ethos
# Those seem to be out of date
#ETHOS_BAUDRATE = 500000
#CFLAGS += -DETHOS_BAUDRATE=$(ETHOS_BAUDRATE)

USEMODULE += stdio_ethos
USEMODULE += auto_init_gnrc_netif
USEMODULE += gnrc_sixlowpan_border_router_default
USEMODULE += gnrc_icmpv6_echo
USEMODULE += gnrc_uhcpc
USEMODULE += fib
# to allow adding a global address to the ethos interface as well
CFLAGS += -DGNRC_NETIF_IPV6_ADDRS_NUMOF=3
endif

ifeq (${OSCORE_CRYPTO_BACKEND},rust)
	# This needs some further drilling down to establish
	EXTRASTACK = 20000
else
	EXTRASTACK = 1500
endif

CFLAGS += -DGCOAP_STACK_SIZE="THREAD_STACKSIZE_DEFAULT + DEBUG_EXTRA_STACKSIZE + sizeof(coap_pkt_t) + ${EXTRASTACK}"
# As the main thread sends messages, it needs an increased size.
CFLAGS += -DTHREAD_STACKSIZE_MAIN="THREAD_STACKSIZE_DEFAULT + THREAD_EXTRA_STACKSIZE_PRINTF + ${EXTRASTACK}"

# Make sanely sized blocks
CFLAGS += -DGCOAP_PDU_BUF_SIZE=600

include ../Makefile.include
