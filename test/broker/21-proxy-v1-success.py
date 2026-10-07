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
        mosq_test.do_send_receive(sock, connect_packet, connack_packet, "connack")
        mosq_test.do_ping(sock)
        sock.close()
        rc = 0

    stde = broker.get_log()
    if rc != 0 or expect_log not in stde:
        print(stde)
        raise ValueError(data)

do_test(b"PROXY TCP4 192.0.2.5 127.0.0.1 6275 1234\r\n", "New client connected from 192.0.2.5:6275")
do_test(b"PROXY TCP6 2001:db8:506:708:900::1 ::1 6275 1234\r\n", "New client connected from 2001:db8:506:708:900::1:6275 as proxy-test (p5, c0, k42)")
do_test(b"PROXY UNKNOWN \r\n", "New client connected from 127.0.0.1:")
