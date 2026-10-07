#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from matchers import Contains
from mosquitto_broker import MosquittoBroker
from proxy_helper import *
import json
import shutil
import socket

mosq_test.require_features(["WITH_WEBSOCKETS", "WITH_WEBSOCKETS_BUILTIN"])

connect_packet = mqtt_packets.gen_connect("proxy-test", keepalive=42, clean_session=False, proto_ver=5)
connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

port = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners=[
        ListenerConfig(
            port=port,
            enable_proxy_protocol=2
        )
    ],
    allow_anonymous=True,
    log_type="all",
)
broker = MosquittoBroker(config=broker_config)
with broker:
    data = b"\x20\x01\x0d\xb8\x05\x06\x07\x08\x09\x00\x00\x00\x00\x00\x00\x01" \
        +  b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        +  b"\x18\x83" + b"\x00\x00"
    sock = do_proxy_v2_connect(port, PROXY_VER, PROXY_CMD_PROXY, PROXY_FAM_IPV6 | PROXY_PROTO_TCP, data)
    mosq_test.do_send_receive(sock, connect_packet, connack_packet, "connack")
    mosq_test.do_ping(sock)
    sock.close()

broker.check_log(Contains("New client connected from 2001:db8:506:708:900::1:6275 as proxy-test (p5, c0, k42)"))
