#!/usr/bin/env python3

# Test whether message size limits apply.

from mosq_test_helper import *
from broker_config import BrokerConfig

def do_test(proto_ver):
    mid = 53
    connect_packet = mqtt_packets.gen_connect("02-subpub-qos0-oversize", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "subpub/qos0/oversize", 0, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=proto_ver)

    connect2_packet = mqtt_packets.gen_connect("02-subpub-qos0-oversize-helper", proto_ver=proto_ver)
    connack2_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    publish_packet_ok = mqtt_packets.gen_publish("subpub/qos0/oversize", qos=0, payload="A", proto_ver=proto_ver)
    publish_packet_bad = mqtt_packets.gen_publish("subpub/qos0/oversize", qos=0, payload="AB", proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(message_size_limit=1)
    broker = MosquittoBroker(port=port, config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=20, port=port)
        sock2.send(publish_packet_ok)
        mosq_test.expect_packet(sock, "publish 1", publish_packet_ok)

        # Check all is still well on the publishing client
        mosq_test.do_ping(sock2)

        sock2.send(publish_packet_bad)

        # Check all is still well on the publishing client
        mosq_test.do_ping(sock2)

        # The subscribing client shouldn't have received a PUBLISH
        mosq_test.do_ping(sock)
        sock.close()


do_test(proto_ver=4)
do_test(proto_ver=5)
