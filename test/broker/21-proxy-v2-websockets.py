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
            enable_proxy_protocol=2,
            protocol="websockets",
        )
    ],
    allow_anonymous=True,
    log_type="all",
)
broker = MosquittoBroker(config=broker_config)
with broker:
    data = b"\xC0\x00\x02\x05" + b"\x00\x00\x00\x00" + b"\x18\x83" + b"\x00\x00"
    sock = do_proxy_v2_connect(port, PROXY_VER, PROXY_CMD_PROXY, PROXY_FAM_IPV4 | PROXY_PROTO_TCP, data)
    websocket_req_good = b"GET /mqtt HTTP/1.1\r\n" \
        + b"Host: localhost\r\n" \
        + b"Upgrade: websocket\r\n" \
        + b"Connection: Upgrade\r\n" \
        + B"Sec-WebSocket-Key: 1JaITHdgDZVd/4OE2AzTTA==\r\n" \
        + b"Sec-WebSocket-Protocol: mqtt\r\n" \
        + b"Sec-WebSocket-Version: 13\r\n" \
        + b"Origin: example.org\r\n" \
        + b"\r\n"

    websocket_resp_good = b"HTTP/1.1 101 Switching Protocols\r\n" \
        + b"Upgrade: WebSocket\r\n" \
        + b"Connection: Upgrade\r\n" \
        + b"Sec-WebSocket-Accept: Ako91O0lxiq8gN0+b9YCijMx8lk=\r\n" \
        + b"Sec-WebSocket-Protocol: mqtt\r\n" \
        + b"\r\n"

    connect_frame = bytearray()
    length = len(connect_packet)
    mask_key = bytearray(os.urandom(4))
    connect_frame.append(0x82) # FIN + opcode
    connect_frame.append(0x80 | length)
    connect_frame.extend(mask_key)
    for i in range(len(connect_packet)):
        connect_frame.append(connect_packet[i] ^ mask_key[i % 4])

    connack_frame = bytearray()
    length = len(connack_packet)
    connack_frame.append(0x82) # FIN + opcode
    connack_frame.append(length)
    for i in range(len(connack_packet)):
        connack_frame.append(connack_packet[i])
    connack_frame = bytes(connack_frame)

    mosq_test.do_send_receive(sock, websocket_req_good, websocket_resp_good, "websocket handshake")
    mosq_test.do_send_receive(sock, connect_frame, connack_frame, "connack")
    sock.close()

broker.check_log(Contains("New client connected from 192.0.2.5:6275"))
