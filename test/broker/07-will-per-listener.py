#!/usr/bin/env python3

# Test whether a client will is transmitted correctly, with per_listener_settings enabled

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

def do_test(proto_ver, clean_session):
    mid = 53
    connect1_packet = mqtt_packets.gen_connect("will-qos0-test", proto_ver=proto_ver)
    connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    connect2_packet = mqtt_packets.gen_connect("test-helper", will_topic="will/qos0/test", will_payload=b"will-message", clean_session=clean_session, proto_ver=proto_ver, session_expiry=60)
    connack2_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "will/qos0/test", 0, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=proto_ver)

    publish_packet = mqtt_packets.gen_publish("will/qos0/test", qos=0, payload="will-message", proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        allow_anonymous=True,
        per_listener_settings=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=5, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, port=port, timeout=5)
        sock2.close()

        mosq_test.expect_packet(sock, "publish", publish_packet)
        sock.close()


do_test(4, True)
do_test(4, False)
do_test(5, True)
do_test(5, False)
