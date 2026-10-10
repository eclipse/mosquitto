#!/usr/bin/env python3

# Test whether the broker correctly reassembles a websocket frame whose header
# (extended payload length and masking key) is split across multiple TCP
# segments. Regression test for a desync in net__read_ws() where header parsing
# was gated on the payload length being zero, causing the remaining length
# bytes and/or masking key to be skipped when fragmented - leaving the stream
# out of sync and rejecting a perfectly valid CONNECT.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_WEBSOCKETS", "WITH_WEBSOCKETS_BUILTIN"])

# Long client id so the CONNECT exceeds 125 bytes and a 2-byte extended
# websocket length is used - that length field is what we fragment.
client_id = "frag-" + "A"*200
connect_packet = mqtt_packets.gen_connect(client_id, keepalive=60, proto_ver=4)
connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=4)

port = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners=[
        ListenerConfig(
            port=port,
            protocol="websockets",
        )
    ],
    allow_anonymous=True,
    log_type="all",
)

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

# Masked binary frame carrying the CONNECT, with a 2-byte extended length.
length = len(connect_packet)
mask_key = bytearray(os.urandom(4))
connect_frame = bytearray()
connect_frame.append(0x82)              # FIN + binary
connect_frame.append(0x80 | 126)        # mask bit + 126 => 2-byte length follows
connect_frame += length.to_bytes(2, "big")
connect_frame += mask_key
for i in range(length):
    connect_frame.append(connect_packet[i] ^ mask_key[i % 4])

connack_frame = bytearray()
connack_frame.append(0x82)
connack_frame.append(len(connack_packet))
connack_frame += connack_packet
connack_frame = bytes(connack_frame)

broker = MosquittoBroker(config=broker_config)
with broker:
    sock = mosq_test.do_client_connect(websocket_req_good, websocket_resp_good, port=port)

    # Send the CONNECT frame fragmented on the length/mask boundaries:
    #   [0:2]  opcode + length-flag byte
    #   [2:3]  first extended-length byte
    #   [3:6]  second length byte + first 2 mask bytes
    #   [6:]   remaining mask bytes + masked payload
    frame = bytes(connect_frame)
    for seg in (frame[0:2], frame[2:3], frame[3:6], frame[6:]):
        sock.send(seg)
        time.sleep(0.05)

    mosq_test.expect_packet(sock, "connack", connack_frame)
    sock.close()

print("Test passed")
