#!/usr/bin/env python3

# Test whether a client will is transmitted correctly.

from mosq_test_helper import *


def do_test(proto_ver, clean_session):
    mid = 53
    connect1_packet = mqtt_packets.gen_connect("will-qos0-test", proto_ver=proto_ver)
    connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    connect2_packet = mqtt_packets.gen_connect("will-qos0-helper", will_topic="will/qos0/test", will_payload=b"will-message", clean_session=clean_session, proto_ver=proto_ver, session_expiry=60)
    connack2_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "will/qos0/test", 0, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=proto_ver)

    publish_packet = mqtt_packets.gen_publish("will/qos0/test", qos=0, payload="will-message", proto_ver=proto_ver)

    connect2_packet_clear = mqtt_packets.gen_connect("will-qos0-helper", proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=5, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, port=port, timeout=5)
        sock2.close()

        mosq_test.expect_packet(sock, "publish", publish_packet)
        sock.close()

        sock = mosq_test.do_client_connect(connect2_packet_clear, connack1_packet, timeout=5, port=port)
        sock.close()


if __name__ == '__main__':
    do_test(proto_ver=4, clean_session=True)
    do_test(proto_ver=4, clean_session=False)
    do_test(proto_ver=5, clean_session=True)
    do_test(proto_ver=5, clean_session=False)
