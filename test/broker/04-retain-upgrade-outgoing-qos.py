#!/usr/bin/env python3

# Test whether a retained PUBLISH to a topic with QoS 0 is sent with subscriber QoS
# when upgrade_outgoing_qos is true

from mosq_test_helper import *
from broker_config import BrokerConfig


def do_test(proto_ver):
    mid = 16
    connect_packet = mqtt_packets.gen_connect("retain-qos0-test", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    publish_packet = mqtt_packets.gen_publish("retain/qos0/test", qos=0, payload="retained message", retain=True, proto_ver=proto_ver)
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "retain/qos0/test", 1, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 1, proto_ver=proto_ver)

    publish_packet2 = mqtt_packets.gen_publish("retain/qos0/test", mid=1, qos=1, payload="retained message", retain=True, proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(upgrade_outgoing_qos=True)
    broker = MosquittoBroker(port=port, config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        sock.send(publish_packet)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        mosq_test.expect_packet(sock, "publish", publish_packet2)
        sock.close()

do_test(proto_ver=4)
do_test(proto_ver=5)
