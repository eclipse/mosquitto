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

def do_test(fam):
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
        data = b"a"*501
        sock = do_proxy_v2_connect(port, PROXY_VER, PROXY_CMD_PROXY, fam | PROXY_PROTO_TCP, data)
        try:
            data = sock.recv(10)
            if len(data) > 0:
                raise ValueError(data)
        except ConnectionResetError:
            pass
        sock.close()
    broker.check_log(Contains("Client (null) [(null):0] disconnected: bad socket read/write: Invalid input"))

do_test(PROXY_FAM_IPV4)
do_test(PROXY_FAM_IPV6)
do_test(PROXY_FAM_UNIX)
