USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
USEMODULE += gnrc_ipv6_default
USEMODULE += gnrc_icmpv6_echo
USEMODULE += gcoap

CFLAGS += -DOSCORE_NANOCOAP_MEMMOVE_MODE

BOARD ?= native
ifneq ($(BOARD),native)
# when using particle-xenon
USEMODULE += auto_init_usbus
USEMODULE += stdio_cdc_acm
USEMODULE += usbus_cdc_ecm
GNRC_NETIF_NUMOF = 2
CFLAGS += -DGNRC_IPV6_NIB_CONF_SLAAC -DGNRC_IPV6_NIB_CONF_ARSM
CFLAGS += -DUSB_CONFIG_VID=0x1209
CFLAGS += -DUSB_CONFIG_PID=0x7D00

CFLAGS += -DTHREAD_STACKSIZE_MAIN=20480
CFLAGS += -DTHREAD_STACKSIZE_DEFAULT=20480
endif

include ../Makefile.include
