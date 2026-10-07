#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_WEBSOCKETS"])

port = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners = [
        ListenerConfig(
            port=port,
            protocol="websockets",
            websockets_origin="example.org"
        )
    ],
    allow_anonymous=True,
)
broker = MosquittoBroker(config=broker_config)
with broker:
    try:
        websocket_req_bad = b"GET /mqtt HTTP/1.1\r\n" \
            + b"Host: localhost\r\n" \
            + b"Upgrade: websocket\r\n" \
            + b"Connection: Upgrade\r\n" \
            + B"Sec-WebSocket-Key: 1JaITHdgDZVd/4OE2AzTTA==\r\n" \
            + b"Sec-WebSocket-Protocol: mqtt\r\n" \
            + b"Sec-WebSocket-Version: 13\r\n" \
            + b"Origin: localhost\r\n" \
            + b"\r\n"

        sock = mosq_test.do_client_connect(websocket_req_bad, b"", port=port)
        sock.close()
    except BrokenPipeError:
        pass

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

    sock = mosq_test.do_client_connect(websocket_req_good, websocket_resp_good, port=port)
    sock.close()
