#!/usr/bin/env python3

# Test whether max_keepalive violations are rejected for MQTT < 5.0.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker


def do_test(proto_ver):
    connect_packet = mqtt_packets.gen_connect("max-keepalive", keepalive=101, proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=2, proto_ver=proto_ver)

    socks = []

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        allow_anonymous=True,
        max_keepalive=100,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        sock.close()

do_test(3)
do_test(4)
