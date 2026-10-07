#!/usr/bin/env python3

# Test whether a client will that is too large is handled

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

def do_test(proto_ver, clean_session):
    mid = 53
    connect_packet = mqtt_packets.gen_connect("will-test", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    connect_packet_ok = mqtt_packets.gen_connect("test-helper", will_topic="will/qos0/test", will_payload=b"A", clean_session=clean_session, proto_ver=proto_ver, session_expiry=60)
    connack_packet_ok = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    connect_packet_bad = mqtt_packets.gen_connect("test-helper", will_topic="will/qos0/test", will_payload=b"AB", clean_session=clean_session, proto_ver=proto_ver, session_expiry=60)
    if proto_ver == 5:
        connack_packet_bad = mqtt_packets.gen_connack(rc=mqtt5_rc.PACKET_TOO_LARGE, proto_ver=proto_ver, property_helper=False)
    else:
        connack_packet_bad = mqtt_packets.gen_connack(rc=5, proto_ver=proto_ver)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "will/qos0/test", 0, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=proto_ver)

    publish_packet = mqtt_packets.gen_publish("will/qos0/test", qos=0, payload="A", proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        allow_anonymous=True,
        message_size_limit=1,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect_packet_bad, connack_packet_bad, port=port, timeout=5)
        sock2.close()

        sock2 = mosq_test.do_client_connect(connect_packet_ok, connack_packet_ok, port=port, timeout=5)
        sock2.close()

        mosq_test.expect_packet(sock, "publish", publish_packet)
        # Check there are no more messages
        mosq_test.do_ping(sock)
        sock.close()


do_test(4, True)
do_test(4, False)
do_test(5, True)
do_test(5, False)
