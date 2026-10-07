#!/usr/bin/env python3

from mosq_test_helper import *


def do_test(proto_ver):
    mid = 3265
    connect_packet = mqtt_packets.gen_connect("03-c2b-qos2-disco-test", clean_session=False, proto_ver=proto_ver, session_expiry=60)
    connack1_packet = mqtt_packets.gen_connack(flags=0, rc=0, proto_ver=proto_ver)
    connect_packet_clear = mqtt_packets.gen_connect("03-c2b-qos2-disco-test", proto_ver=proto_ver)

    if proto_ver == 3:
        connack2_packet = mqtt_packets.gen_connack(flags=0, rc=0, proto_ver=proto_ver)
    else:
        connack2_packet = mqtt_packets.gen_connack(flags=1, rc=0, proto_ver=proto_ver)

    helper_connect_packet = mqtt_packets.gen_connect("03-c2b-qos2-disco-helper", clean_session=True, proto_ver=proto_ver)
    helper_connack_packet = mqtt_packets.gen_connack(flags=0, rc=0, proto_ver=proto_ver)
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "03/c2b/qos2/disconnect/test", 2, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 2, proto_ver=proto_ver)

    mid = 1
    publish_packet = mqtt_packets.gen_publish("03/c2b/qos2/disconnect/test", qos=2, mid=mid, payload="disconnect-message", proto_ver=proto_ver)
    publish_dup_packet = mqtt_packets.gen_publish("03/c2b/qos2/disconnect/test", qos=2, mid=mid, payload="disconnect-message", dup=True, proto_ver=proto_ver)
    pubrec_packet = mqtt_packets.gen_pubrec(mid, proto_ver=proto_ver)
    pubrel_packet = mqtt_packets.gen_pubrel(mid, proto_ver=proto_ver)
    if proto_ver == 3:
        pubrel_dup_packet = mqtt_packets.gen_pubrel(mid, dup=True, proto_ver=proto_ver)
    else:
        pubrel_dup_packet = mqtt_packets.gen_pubrel(mid, dup=False, proto_ver=proto_ver)
    pubcomp_packet = mqtt_packets.gen_pubcomp(mid, proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)

    with broker:
        # Add a subscriber, so we ensure that the QoS 2 flow must be completed
        helper = mosq_test.do_client_connect(helper_connect_packet, helper_connack_packet, port=port)
        mosq_test.do_send_receive(helper, subscribe_packet, suback_packet)

        sock = mosq_test.do_client_connect(connect_packet, connack1_packet, port=port)

        mosq_test.do_send_receive(sock, publish_packet, pubrec_packet, "pubrec")

        # We're now going to disconnect and pretend we didn't receive the pubrec.
        sock.close()

        sock = mosq_test.do_client_connect(connect_packet, connack2_packet, port=port, connack_error="connack 2")
        sock.send(publish_dup_packet)

        mosq_test.expect_packet(sock, "pubrec", pubrec_packet)
        mosq_test.do_send_receive(sock, pubrel_packet, pubcomp_packet, "pubcomp")

        # Again, pretend we didn't receive this pubcomp
        sock.close()

        sock = mosq_test.do_client_connect(connect_packet, connack2_packet, port=port)
        mosq_test.do_send_receive(sock, pubrel_dup_packet, pubcomp_packet, "pubcomp")
        sock.close()
        helper.close()

        # Clear session
        sock = mosq_test.do_client_connect(connect_packet_clear, connack1_packet, port=port, connack_error="connack clear")
        sock.close()


if __name__ == '__main__':
    do_test(proto_ver=3)
    do_test(proto_ver=4)
    do_test(proto_ver=5)
