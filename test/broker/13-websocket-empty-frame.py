#!/usr/bin/env python3

# Test whether the broker keeps an MQTT session intact when a client sends a
# websocket data frame with an empty payload. Such a frame is valid - RFC 6455
# permits a zero-length payload, and MQTT treats websocket framing as a
# transparent carrier for the MQTT byte stream, so a frame contributing no
# bytes must simply be consumed - but net__read_ws() returned a positive byte
# count for it without writing anything to the caller's buffer. The MQTT parser
# then treated that many stale buffer bytes as packet data, desynchronising the
# stream: the session stopped responding and was dropped.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_WEBSOCKETS", "WITH_WEBSOCKETS_BUILTIN"])

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

websocket_req = b"GET /mqtt HTTP/1.1\r\n" \
    + b"Host: localhost\r\n" \
    + b"Upgrade: websocket\r\n" \
    + b"Connection: Upgrade\r\n" \
    + B"Sec-WebSocket-Key: 1JaITHdgDZVd/4OE2AzTTA==\r\n" \
    + b"Sec-WebSocket-Protocol: mqtt\r\n" \
    + b"Sec-WebSocket-Version: 13\r\n" \
    + b"\r\n"

websocket_resp = b"HTTP/1.1 101 Switching Protocols\r\n" \
    + b"Upgrade: WebSocket\r\n" \
    + b"Connection: Upgrade\r\n" \
    + b"Sec-WebSocket-Accept: Ako91O0lxiq8gN0+b9YCijMx8lk=\r\n" \
    + b"Sec-WebSocket-Protocol: mqtt\r\n" \
    + b"\r\n"


def client_frame(payload):
    """A masked binary frame, as a client must send."""
    mask_key = bytearray(os.urandom(4))
    frame = bytearray()
    frame.append(0x82)                      # FIN + binary
    length = len(payload)
    if length < 126:
        frame.append(0x80 | length)         # mask bit + length
    else:
        frame.append(0x80 | 126)
        frame += length.to_bytes(2, "big")
    frame += mask_key
    for i in range(length):
        frame.append(payload[i] ^ mask_key[i % 4])
    return bytes(frame)


def server_frame(payload):
    """A frame as the broker sends it: binary, unmasked."""
    frame = bytearray()
    frame.append(0x82)
    frame.append(len(payload))
    frame += payload
    return bytes(frame)


connack_frame = server_frame(mqtt_packets.gen_connack(rc=0, proto_ver=4))
pingresp_frame = server_frame(mqtt_packets.gen_pingresp())
suback_frame = server_frame(mqtt_packets.gen_suback(mid=1, qos=0, proto_ver=4))

broker = MosquittoBroker(config=broker_config)
with broker:
    # An empty frame before anything else: the CONNECT that follows it must
    # still be read as a CONNECT.
    sock = mosq_test.do_client_connect(websocket_req, websocket_resp, port=port)
    sock.send(client_frame(b""))
    sock.send(client_frame(mqtt_packets.gen_connect("empty-frame-first", keepalive=60, proto_ver=4)))
    mosq_test.expect_packet(sock, "connack", connack_frame)
    sock.close()

    # An empty frame in the middle of an established session: what follows must
    # still be understood, and the session must survive.
    sock = mosq_test.do_client_connect(websocket_req, websocket_resp, port=port)
    sock.send(client_frame(mqtt_packets.gen_connect("empty-frame-mid", keepalive=60, proto_ver=4)))
    mosq_test.expect_packet(sock, "connack", connack_frame)

    sock.send(client_frame(b""))
    sock.send(client_frame(mqtt_packets.gen_pingreq()))
    mosq_test.expect_packet(sock, "pingresp", pingresp_frame)

    # And again before a packet with a payload of its own, so that the check is
    # not specific to a two-byte one.
    sock.send(client_frame(b""))
    sock.send(client_frame(mqtt_packets.gen_subscribe(mid=1, topic="empty/frame", qos=0, proto_ver=4)))
    mosq_test.expect_packet(sock, "suback", suback_frame)
    sock.close()

    # Several empty frames in a row, since each one is consumed separately.
    sock = mosq_test.do_client_connect(websocket_req, websocket_resp, port=port)
    for _ in range(5):
        sock.send(client_frame(b""))
    sock.send(client_frame(mqtt_packets.gen_connect("empty-frames-many", keepalive=60, proto_ver=4)))
    mosq_test.expect_packet(sock, "connack", connack_frame)
    sock.close()

print("Test passed")
