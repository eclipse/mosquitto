#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker
from proxy_helper import *
import json
import shutil
import socket

mosq_test.require_features(["WITH_WEBSOCKETS", "WITH_WEBSOCKETS_BUILTIN"])

connect_packet = mqtt_packets.gen_connect("proxy-test", keepalive=42, clean_session=False, proto_ver=5)
connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

def do_test(header):
    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners=[ ListenerConfig(port=port, enable_proxy_protocol=2) ],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("localhost", port))
        sock.send(header)
        sock.close()

# This test essentially should never fail, but it covers a code path that is
# not covered by the other tests and should be used with valgrind/sanitisers

# Not enough data, IPv4
proxy_header = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a" + b"\x21\x11\x00\x0f" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x00\x00"
do_test(proxy_header)
