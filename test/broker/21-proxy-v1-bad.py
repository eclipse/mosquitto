#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker
from proxy_helper import *
import json
import shutil
import socket

mosq_test.require_features(["WITH_WEBSOCKETS", "WITH_WEBSOCKETS_BUILTIN"])

def do_test(data, expect_log):
    rc = 1
    connect_packet = mqtt_packets.gen_connect("proxy-test", keepalive=42, clean_session=False, proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners=[ ListenerConfig(port=port, enable_proxy_protocol=1) ],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = do_proxy_v1_connect(port, data)
        try:
            d = sock.recv(1)
            if len(d) == 0:
                rc = 0
        except ConnectionResetError:
            rc = 0
        sock.close()

    stde = broker.get_log()
    if rc != 0 or expect_log not in stde:
        print(stde)
        raise ValueError(data)


# Basic
do_test(b"PROXY TCP3 192.0.2.5 127.0.0.1 6275 1234\r\n", "Connection rejected, corrupt PROXY header.") # Bad transport
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 1234                                                                   \r\n", "Connection rejected, corrupt PROXY header.") # Too long

# TCP4
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1 6275\r\n", "Connection rejected, corrupt PROXY header.") # Missing dport
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1\r\n", "Connection rejected, corrupt PROXY header.") # Missing sport
do_test(b"PROXY TCP4 192.0.2.5\r\n", "Connection rejected, corrupt PROXY header.") # Missing daddr
do_test(b"PROXY TCP4 \r\n", "Connection rejected, corrupt PROXY header.") # Missing saddr
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 0\r\n", "Connection rejected, corrupt PROXY header.") # dport == 0
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 65536\r\n", "Connection rejected, corrupt PROXY header.") # dport == 65536
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1 0 1234\r\n", "Connection rejected, corrupt PROXY header.") # sport == 0
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1 65536 1234\r\n", "Connection rejected, corrupt PROXY header.") # sport == 65536
do_test(b"PROXY TCP4 192.0.2.5 127.0.0.256 6275 1234\r\n", "Connection rejected, corrupt PROXY header.") # daddr invalid
do_test(b"PROXY TCP4 192.0.2.256 127.0.0.1 6275 1234\r\n", "Connection rejected, corrupt PROXY header.") # saddr invalid

# TCP6
do_test(b"PROXY TCP6 192.0.2.5 127.0.0.1 6275\r\n", "Connection rejected, corrupt PROXY header.") # Missing dport
do_test(b"PROXY TCP6 192.0.2.5 127.0.0.1\r\n", "Connection rejected, corrupt PROXY header.") # Missing sport
do_test(b"PROXY TCP6 192.0.2.5\r\n", "Connection rejected, corrupt PROXY header.") # Missing daddr
do_test(b"PROXY TCP6 \r\n", "Connection rejected, corrupt PROXY header.") # Missing saddr
do_test(b"PROXY TCP6 192.0.2.5 127.0.0.1 6275 0\r\n", "Connection rejected, corrupt PROXY header.") # dport == 0
do_test(b"PROXY TCP6 192.0.2.5 127.0.0.1 6275 65536\r\n", "Connection rejected, corrupt PROXY header.") # dport == 65536
do_test(b"PROXY TCP6 192.0.2.5 127.0.0.1 0 1234\r\n", "Connection rejected, corrupt PROXY header.") # sport == 0
do_test(b"PROXY TCP6 192.0.2.5 127.0.0.1 65536 1234\r\n", "Connection rejected, corrupt PROXY header.") # sport == 65536
do_test(b"PROXY TCP6 192.0.2.5 127.0.0.256 6275 1234\r\n", "Connection rejected, corrupt PROXY header.") # daddr invalid
do_test(b"PROXY TCP6 192.0.2.256 127.0.0.1 6275 1234\r\n", "Connection rejected, corrupt PROXY header.") # saddr invalid
