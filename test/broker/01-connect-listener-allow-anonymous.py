#!/usr/bin/env python3

# Test whether an anonymous connection is correctly denied.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker


def do_test(allow, lallow1, lallow2, expect_success1, expect_success2):
    port1, port2 = mosq_test.get_port(2)
    broker_config = BrokerConfig(
        listeners = [
            ListenerConfig(
                port=port1,
                listener_allow_anonymous=lallow1,
            ),
            ListenerConfig(
                port=port2,
                listener_allow_anonymous=lallow2,
            ),
        ],
        allow_anonymous=allow,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        for proto_ver in [4, 5]:
            connect_packet = mqtt_packets.gen_connect(f"connect-anon-test-{proto_ver}-{expect_success1}-{expect_success2}", proto_ver=proto_ver)

            if proto_ver == 5:
                connack_packet_success = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
                connack_packet_rejected = mqtt_packets.gen_connack(rc=mqtt5_rc.NOT_AUTHORIZED, proto_ver=proto_ver, properties=None)
            else:
                connack_packet_success = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
                connack_packet_rejected = mqtt_packets.gen_connack(rc=5, proto_ver=proto_ver)

            if expect_success1:
                sock = mosq_test.do_client_connect(connect_packet, connack_packet_success, port=port1)
            else:
                sock = mosq_test.do_client_connect(connect_packet, connack_packet_rejected, port=port1)
            sock.close()

            if expect_success2:
                sock = mosq_test.do_client_connect(connect_packet, connack_packet_success, port=port2)
            else:
                sock = mosq_test.do_client_connect(connect_packet, connack_packet_rejected, port=port2)
            sock.close()


tests = [
    {"allow":None,  "lallow1":False, "lallow2":False, "success1":False, "success2":False},
    {"allow":None,  "lallow1":True,  "lallow2":False, "success1":True,  "success2":False},
    {"allow":None,  "lallow1":False, "lallow2":True,  "success1":False, "success2":True},
    {"allow":False, "lallow1":False, "lallow2":False, "success1":False, "success2":False},
    {"allow":False, "lallow1":True,  "lallow2":False, "success1":True,  "success2":False},
    {"allow":False, "lallow1":False, "lallow2":True,  "success1":False, "success2":True},
    {"allow":True,  "lallow1":False, "lallow2":False, "success1":False, "success2":False},
    {"allow":True,  "lallow1":True,  "lallow2":False, "success1":True,  "success2":False},
    {"allow":True,  "lallow1":False, "lallow2":True,  "success1":False, "success2":True},
]

for t in tests:
    do_test(t["allow"], t["lallow1"], t["lallow2"], t["success1"], t["success2"])
