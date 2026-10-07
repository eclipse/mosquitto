#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from matchers import Contains
from mosquitto_broker import MosquittoBroker
from proxy_helper import *
import json
import shutil
import socket

mosq_test.require_features(["WITH_TLS", "WITH_WEBSOCKETS", "WITH_WEBSOCKETS_BUILTIN"])

def do_test(data):
    connect_packet = mqtt_packets.gen_connect("proxy-test", keepalive=42, clean_session=False, proto_ver=5, username="none", password="pw")
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners=[
            ListenerConfig(
                port=port,
                enable_proxy_protocol=2,
                require_certificate=True,
                use_identity_as_username=True,
            )
        ],
        allow_anonymous=True,
        log_type="all",
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = do_proxy_v2_connect(port, PROXY_VER, PROXY_CMD_PROXY, PROXY_FAM_IPV4 | PROXY_PROTO_TCP, data)
        mosq_test.do_send_receive(sock, connect_packet, connack_packet, "connack")
        mosq_test.do_ping(sock)
        sock.close()
    broker.check_log(Contains("New client connected from 192.0.2.5:6275 as proxy-test (p5, c0, k42, u'ppppppp')."))

data = b"\xC0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00" \
    + b"\x20" \
    + b"\x00\x19" \
    + b"\x05" \
    + b"\x00\x00\x00\x00" \
    + b"\x21" \
    + b"\x00\x07" \
    + b"\x54\x4C\x53\x76\x31\x2E\x33" \
    + b"\x22" \
    + b"\x00\x07" \
    + b"\x70\x70\x70\x70\x70\x70\x70"
do_test(data)
