#!/usr/bin/env python3

# Test whether a client will is transmitted correctly with a null payload.

from mosq_test_helper import *

def helper(port, proto_ver):
    connect_packet = mqtt_packets.gen_connect("07-will-null-helper", will_topic="will/null/test", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    sock.close()

def do_test(proto_ver):
    mid = 53
    connect_packet = mqtt_packets.gen_connect("07-will-null-test", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "will/null/test", 0, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=proto_ver)

    publish_packet = mqtt_packets.gen_publish("will/null/test", qos=0, proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=30, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        helper(port, proto_ver)
        mosq_test.expect_packet(sock, "publish", publish_packet)
        sock.close()


if __name__ == '__main__':
    do_test(proto_ver=4)
    do_test(proto_ver=5)
