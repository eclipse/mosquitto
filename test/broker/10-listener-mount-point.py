#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

def helper(port, proto_ver):
    connect_packet = mqtt_packets.gen_connect("10-listener-mount-helper", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    publish_packet = mqtt_packets.gen_publish("10/listener/mount/test", qos=0, payload="mount point", proto_ver=proto_ver)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port, connack_error="helper connack")
    sock.send(publish_packet)
    sock.close()


def do_test(proto_ver):
    mid = 1

    # Subscriber for listener with mount point
    connect_packet1 = mqtt_packets.gen_connect("test1", proto_ver=proto_ver)
    connack_packet1 = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
    subscribe_packet1 = mqtt_packets.gen_subscribe(mid, "#", 0, proto_ver=proto_ver)
    suback_packet1 = mqtt_packets.gen_suback(mid, 0, proto_ver=proto_ver)
    publish_packet1 = mqtt_packets.gen_publish("mount/10/listener/mount/test", qos=0, payload="mount point", proto_ver=proto_ver)

    # Subscriber for listener without mount point
    connect_packet2 = mqtt_packets.gen_connect("test2", proto_ver=proto_ver)
    connack_packet2 = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
    subscribe_packet2 = mqtt_packets.gen_subscribe(mid, "#", 0, proto_ver=proto_ver)
    suback_packet2 = mqtt_packets.gen_suback(mid, 0, proto_ver=proto_ver)
    publish_packet2 = mqtt_packets.gen_publish("10/listener/mount/test", qos=0, payload="mount point", proto_ver=proto_ver)

    (port1, port2) = mosq_test.get_port(2)
    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [
            ListenerConfig(port=port1),
            ListenerConfig(
                port=port2,
                mount_point="mount/",
            )
        ],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock1 = mosq_test.do_client_connect(connect_packet1, connack_packet1, timeout=20, port=port1)
        mosq_test.do_send_receive(sock1, subscribe_packet1, suback_packet1, "suback1")

        sock2 = mosq_test.do_client_connect(connect_packet2, connack_packet2, timeout=20, port=port2)
        mosq_test.do_send_receive(sock2, subscribe_packet2, suback_packet2, "suback2")

        helper(port2, proto_ver)
        # Should have now received a publish command

        mosq_test.expect_packet(sock1, "publish1", publish_packet1)
        mosq_test.expect_packet(sock2, "publish2", publish_packet2)
        sock1.close()
        sock2.close()


do_test(proto_ver=4)
do_test(proto_ver=5)
