#!/usr/bin/env python3

# Test whether message size limits apply.

from mosq_test_helper import *

from broker_config import BrokerConfig
from mosquitto_broker import MosquittoBroker

def do_test(proto_ver):
    mid = 53
    connect_packet = mqtt_packets.gen_connect("subpub-qos1-oversize", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "subpub/qos1/oversize", 1, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 1, proto_ver=proto_ver)

    connect2_packet = mqtt_packets.gen_connect("subpub-qos1-oversize-helper", proto_ver=proto_ver)
    connack2_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 1
    publish_packet_ok = mqtt_packets.gen_publish("subpub/qos1/oversize", mid=mid, qos=1, payload="A", proto_ver=proto_ver)
    puback_packet_ok = mqtt_packets.gen_puback(mid=mid, proto_ver=proto_ver)

    mid = 2
    publish_packet_bad = mqtt_packets.gen_publish("subpub/qos1/oversize", mid=mid, qos=1, payload="AB", proto_ver=proto_ver)
    if proto_ver == 5:
        puback_packet_bad = mqtt_packets.gen_puback(reason_code=mqtt5_rc.PACKET_TOO_LARGE, mid=mid, proto_ver=proto_ver)
    else:
        puback_packet_bad = mqtt_packets.gen_puback(mid=mid, proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        allow_anonymous=True,
        message_size_limit=1,
    )
    broker = MosquittoBroker(port=port, config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock2, publish_packet_ok, puback_packet_ok, "puback 1")
        mosq_test.expect_packet(sock, "publish 1", publish_packet_ok)
        sock.send(puback_packet_ok)

        # Check all is still well on the publishing client
        mosq_test.do_ping(sock2)

        mosq_test.do_send_receive(sock2, publish_packet_bad, puback_packet_bad, "puback 2")

        # The subscribing client shouldn't have received a PUBLISH
        mosq_test.do_ping(sock)


do_test(proto_ver=4)
do_test(proto_ver=5)
