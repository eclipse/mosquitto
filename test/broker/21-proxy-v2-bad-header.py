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

def do_test(headers):
    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners=[
            ListenerConfig(
                port=port,
                enable_proxy_protocol=2
            )
        ],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        for header in headers:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(("localhost", port))
            sock.send(header)
            try:
                data = sock.recv(10)
                if len(data) == 0:
                    sock.close()
                    continue
            except ConnectionResetError:
                sock.close()
                continue
            raise RuntimeError("sock was not closed")


magic = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"

proxy_headers = []
# Bad magic
proxy_headers.append(b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0b" + b"\x21\x01\x00\x0c" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x00\x00")

# Bad version
proxy_headers.append(magic + b"\x31\x01\x00\x0c" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x00\x00")

# Bad command
proxy_headers.append(magic + b"\x23\x01\x00\x0c" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x00\x00")

# Bad family (proxy command with unspecified family)
proxy_headers.append(magic + b"\x21\x00\x00\x0c" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x00\x00")

# Short length IPv4
proxy_headers.append(magic + b"\x21\x11\x00\x0b" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x00\x00")

# IPv4 with header zero length
proxy_headers.append(magic + b"\x21\x11\x00\x00" + b"\xc0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00")

# Short length IPv6
proxy_headers.append(magic + b"\x21\x21\x00\x0b" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x00\x00")

# IPv6 with header zero length
proxy_headers.append(magic + b"\x21\x21\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x00\x00")

# Unix sock with header zero length
proxy_headers.append(magic + b"\x21\x31\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x00\x00")

# Short SSL TLV
proxy_headers.append(magic + b"\x21\x11\x00\x10" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x20" + b"\x00\x01" + b"\x21\x00")

# Too long SSL TLV for overall length
proxy_headers.append(magic + b"\x21\x11\x00\x10" + b"\xC0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00" \
    + b"\x20" \
    + b"\x00\x19" \
    + b"\x05" \
    + b"\x00\x00\x00\x00" \
    + b"\x21" \
    + b"\x00\x07" \
    + b"\x54\x4C\x53\x76\x31\x2E\x33" \
    + b"\x23" \
    + b"\x00\x08" \
    + b"\x70\x71\x72\x73\x74\x75\x76")

# Too long SSL sub TLV for overall length
proxy_headers.append(magic + b"\x21\x11\x00\x28" + b"\xC0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00" \
    + b"\x20" \
    + b"\x00\x19" \
    + b"\x05" \
    + b"\x00\x00\x00\x00" \
    + b"\x21" \
    + b"\x00\x07" \
    + b"\x54\x4C\x53\x76\x31\x2E\x33" \
    + b"\x23" \
    + b"\x00\x0A" \
    + b"\x70\x71\x72\x73\x74\x75\x76")

do_test(proxy_headers)
