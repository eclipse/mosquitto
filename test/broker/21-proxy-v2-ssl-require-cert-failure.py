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
    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners=[
            ListenerConfig(
                port=port,
                enable_proxy_protocol=2,
                require_certificate=True,
            )
        ],
        allow_anonymous=True,
        log_type="all",
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = do_proxy_v2_connect(port, PROXY_VER, PROXY_CMD_PROXY, PROXY_FAM_IPV4 | PROXY_PROTO_TCP, data)
        try:
            data = sock.recv(10)
            if len(data) > 0:
                raise ValueError(data)
        except ConnectionResetError:
            pass
        sock.close()
    broker.check_log(Contains("Connection from 192.0.2.5:6275 rejected, client did not provide a certificate."))

# No SSL at all
data = b"\xC0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00"
do_test(data)

# SSL but no certificate at all - this should fail
# IP, IP, port, port, SSL-tlv, length, client, verify, SSL-version sub-tlv, length, value
data = b"\xC0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00" \
    + b"\x20" \
    + b"\x00\x0F" \
    + b"\x01" \
    + b"\x00\x00\x00\x01" \
    + b"\x21" \
    + b"\x00\x07" \
    + b"\x54\x4C\x53\x76\x31\x2E\x33"
do_test(data)

# SSL, verify 0 but no certificate presented this session
# IP, IP, port, port, SSL-tlv, length, client, verify, SSL-version sub-tlv, length, value
data = b"\xC0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00" \
    + b"\x20" \
    + b"\x00\x0F" \
    + b"\x01" \
    + b"\x00\x00\x00\x00" \
    + b"\x21" \
    + b"\x00\x07" \
    + b"\x54\x4C\x53\x76\x31\x2E\x33"
do_test(data)
