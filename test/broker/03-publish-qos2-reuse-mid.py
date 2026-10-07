#!/usr/bin/env python3

# Test what happens if a client reuses an in-use mid with a different message.

from mosq_test_helper import *

def do_test(proto_ver):
    connect_packet = mqtt_packets.gen_connect("pub-qos2-test", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 312
    publish_packet1 = mqtt_packets.gen_publish("pub/qos2/test", qos=2, mid=mid, payload="message", proto_ver=proto_ver)
    pubrec_packet = mqtt_packets.gen_pubrec(mid, proto_ver=proto_ver)
    pubrel_packet = mqtt_packets.gen_pubrel(mid, proto_ver=proto_ver)
    pubcomp_packet = mqtt_packets.gen_pubcomp(mid, proto_ver=proto_ver)

    mid = 312
    publish_packet2 = mqtt_packets.gen_publish("pub/qos2/reuse", qos=2, mid=mid, payload="message", proto_ver=proto_ver)

    sub_connect_packet = mqtt_packets.gen_connect("sub-qos2-test", proto_ver=proto_ver)
    sub_connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "#", 2, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 2, proto_ver=proto_ver)
    mid = 1
    publish_packet_expected = mqtt_packets.gen_publish("pub/qos2/reuse", qos=2, mid=mid, payload="message", proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        ssock = mosq_test.do_client_connect(sub_connect_packet, sub_connack_packet, port=port)
        mosq_test.do_send_receive(ssock, subscribe_packet, suback_packet, "suback")

        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, publish_packet1, pubrec_packet, "pubrec1")
        mosq_test.do_send_receive(sock, publish_packet2, pubrec_packet, "pubrec2")
        mosq_test.do_send_receive(sock, pubrel_packet, pubcomp_packet, "pubcomp")

        mosq_test.expect_packet(ssock, "publish", publish_packet_expected)
        sock.close()


if __name__ == '__main__':
    do_test(proto_ver=4)
    do_test(proto_ver=5)
