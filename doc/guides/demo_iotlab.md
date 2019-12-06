@page demo_iotlab Demo: Pulling large amounts of data from a device at IoT Lab using block-wise transfer

This guide is incomplete and so far only consists of notes-to-self.

---

* get account
* set up ssh
* ensure you have v6 outward
* `make BOARD=iotlab-m3 all`
* take elf, upload to m3 (eg. in grenoble)
* log in::

    $ sudo ethos_uhcpd.py m3-100 tap0 2001:660:5307:3100::1/64
    > help
    (don't be afraid, just enter when ready, first prompt was not recorded)
    > ifconfig
    Iface  7  HWaddr: 11:15  Channel: 26  Page: 0  NID: 0x23
              Long HWaddr: 22:5C:FC:65:10:6B:11:15
               TX-Power: 0dBm  State: IDLE  max. Retrans.: 3  CSMA Retries: 4
              AUTOACK  ACK_REQ  CSMA  L2-PDU:102 MTU:1280  HL:64  RTR
              RTR_ADV  6LO  IPHC
              Source address length: 8
              Link type: wireless
              inet6 addr: fe80::205c:fc65:106b:1115  scope: link  VAL
              inet6 addr: 2001:660:5307:3100:205c:fc65:106b:1115  scope: global  VAL
              inet6 group: ff02::2
              inet6 group: ff02::1
              inet6 group: ff02::1:ff6b:1115

    Iface  8  HWaddr: 02:90:76:ED:42:49
              L2-PDU:1500 MTU:1500  HL:64  RTR
              RTR_ADV  Source address length: 6
              Link type: wired                                                                                                                                               inet6 addr: fe80::90:76ff:feed:4249  scope: link  VAL
              inet6 addr: fe80::2  scope: link  VAL
              inet6 group: ff02::2
              inet6 group: ff02::1
              inet6 group: ff02::1:ffed:4249
              inet6 group: ff02::1:ff00:2
    > ifconfig 8 add 2001:660:5307:3100:205c:fc65:106b:1116/64

    (picking m3-100 from experiment list, tap0 from the list of free interfaces on `ip l`, the subnet from your host's range at https://www.iot-lab.info/tutorials/understand-ipv6-subnetting-on-the-fit-iot-lab-testbed/, 7 the wired interface and :1116 any other address in the subnet)
    (is necessary b/c server operation on BR seems to be a corner case, usually routing, and ping works to :1115 as well)

* similar context to peertopeer's context
* feed oscore-key-derivation your-key server -- may need to ^D inbetween due to terminal buffer configuration
* riotserver.json: {"coap://[2001:660:5307:3100:205c:fc65:106b:1116]/*": { "oscore": {"contextfile": "./my-context/", "role": "client" } }}
* ./aiocoap-client 'coap://[2001:660:5307:3100:205c:fc65:106b:1116]/sensordata' --credentials ./riotserver.json -vv
