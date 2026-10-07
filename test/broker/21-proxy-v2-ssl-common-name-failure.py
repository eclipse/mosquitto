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

def do_test(data, expect_log):
    connect_packet = mqtt_packets.gen_connect("proxy-test", keepalive=42, clean_session=False, proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=134, proto_ver=5)

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
        sock.send(connect_packet)
        try:
            mosq_test.expect_packet(sock, "connack", connack_packet)
            data = sock.recv(10)
            if len(data) > 0:
                raise ValueError(data)
        except (BrokenPipeError, ConnectionResetError):
            pass
        sock.close()
    broker.check_log(Contains(expect_log))

# No SSL at all
data = b"\xC0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00"
expect_log = "rejected, client did not provide a certificate."
do_test(data, expect_log)

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
expect_log = "rejected, client did not provide a certificate."
do_test(data, expect_log)

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
expect_log = "rejected, client did not provide a certificate."
do_test(data, expect_log)

data = b"\xC0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00" \
    + b"\x20" \
    + b"\x00\x0F" \
    + b"\x05" \
    + b"\x00\x00\x00\x00" \
    + b"\x21" \
    + b"\x00\x07" \
    + b"\x54\x4C\x53\x76\x31\x2E\x33"
expect_log = "Client proxy-test [192.0.2.5:6275] disconnected: not authorised."
do_test(data, expect_log)
