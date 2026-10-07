#!/usr/bin/env python3

from mosq_test_helper import *
from broker_config import BrokerConfig

def do_test(proto_ver):
    connect_packet = mqtt_packets.gen_connect("subpub-qos0-bytes", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    connect_packet_helper = mqtt_packets.gen_connect("qos0-bytes-helper", proto_ver=proto_ver)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "subpub/qos0/queued/bytes", 1, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 1, proto_ver=proto_ver)

    publish_packet0 = mqtt_packets.gen_publish("subpub/qos0/queued/bytes", qos=0, payload="message", proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        max_inflight_messages=20,
        max_inflight_bytes=1000000,
        max_queued_messages=20,
        max_queued_bytes=1000000,
    )
    broker = MosquittoBroker(port=port, config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=4, port=port, connack_error="connack 1")

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        helper = mosq_test.do_client_connect(connect_packet_helper, connack_packet, timeout=4, port=port, connack_error="connack helper")

        helper.send(publish_packet0)
        mosq_test.expect_packet(sock, "publish0", publish_packet0)
        sock.close()


do_test(proto_ver=4)
do_test(proto_ver=5)
exit(0)
