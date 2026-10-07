#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker
from proxy_helper import *
import json
import shutil
import socket

mosq_test.require_features(["WITH_WEBSOCKETS", "WITH_WEBSOCKETS_BUILTIN"])

def do_test(header):
    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners=[ ListenerConfig(port=port, enable_proxy_protocol=2) ],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("localhost", port))
        sock.send(header)
        try:
            data = sock.recv(10)
            if len(data) == 0:
                sock.close()
                return
        except ConnectionResetError:
            sock.close()
            return
        raise RuntimeError("sock was not closed")

proxy_header = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a" + b"\x20\x00\x00\x00"
do_test(proxy_header)
