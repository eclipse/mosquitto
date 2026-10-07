#!/usr/bin/env python3

# Does the broker respect receive maximum==2?
# MQTT v5

from mosq_test_helper import *

def helper(port):
    rc = 1
    connect_packet = mqtt_packets.gen_connect("subpub-qos2-recv-max2-helper", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    mid = 1
    publish_packet = mqtt_packets.gen_publish("subpub/qos2/receive/maximum2", qos=2, mid=mid, payload="message1", proto_ver=5)
    pubrec_packet = mqtt_packets.gen_pubrec(mid, proto_ver=5)
    pubrel_packet = mqtt_packets.gen_pubrel(mid, proto_ver=5)
    pubcomp_packet = mqtt_packets.gen_pubcomp(mid, proto_ver=5)

    mid = 2
    publish_packet2 = mqtt_packets.gen_publish("subpub/qos2/receive/maximum2", qos=2, mid=mid, payload="message2", proto_ver=5)
    pubrec_packet2 = mqtt_packets.gen_pubrec(mid, proto_ver=5)
    pubrel_packet2 = mqtt_packets.gen_pubrel(mid, proto_ver=5)
    pubcomp_packet2 = mqtt_packets.gen_pubcomp(mid, proto_ver=5)

    mid = 3
    publish_packet3 = mqtt_packets.gen_publish("subpub/qos2/receive/maximum2", qos=2, mid=mid, payload="message3", proto_ver=5)
    pubrec_packet3 = mqtt_packets.gen_pubrec(mid, proto_ver=5)
    pubrel_packet3 = mqtt_packets.gen_pubrel(mid, proto_ver=5)
    pubcomp_packet3 = mqtt_packets.gen_pubcomp(mid, proto_ver=5)


    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

    mosq_test.do_send_receive(sock, publish_packet, pubrec_packet, "pubrec")
    mosq_test.do_send_receive(sock, pubrel_packet, pubcomp_packet, "pubcomp")

    mosq_test.do_send_receive(sock, publish_packet2, pubrec_packet2, "pubrec2")
    mosq_test.do_send_receive(sock, pubrel_packet2, pubcomp_packet2, "pubcomp2")

    mosq_test.do_send_receive(sock, publish_packet3, pubrec_packet3, "pubrec3")
    mosq_test.do_send_receive(sock, pubrel_packet3, pubcomp_packet3, "pubcomp3")
    sock.close()


def do_test(proto_ver):
    if proto_ver == 4:
        exit(0)

    rc = 1
    props = mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 2)
    connect_packet = mqtt_packets.gen_connect("subpub-qos2-recv-max2", proto_ver=5, properties=props)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "subpub/qos2/receive/maximum2", 2, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid, 2, proto_ver=5)

    mid = 1
    publish_packet1 = mqtt_packets.gen_publish("subpub/qos2/receive/maximum2", qos=2, mid=mid, payload="message1", proto_ver=5)
    pubrec_packet1 = mqtt_packets.gen_pubrec(mid, proto_ver=5)
    pubrel_packet1 = mqtt_packets.gen_pubrel(mid, proto_ver=5)
    pubcomp_packet1 = mqtt_packets.gen_pubcomp(mid, proto_ver=5)

    mid = 2
    publish_packet2 = mqtt_packets.gen_publish("subpub/qos2/receive/maximum2", qos=2, mid=mid, payload="message2", proto_ver=5)
    pubrec_packet2 = mqtt_packets.gen_pubrec(mid, proto_ver=5)
    pubrel_packet2 = mqtt_packets.gen_pubrel(mid, proto_ver=5)
    pubcomp_packet2 = mqtt_packets.gen_pubcomp(mid, proto_ver=5)

    mid = 3
    publish_packet3 = mqtt_packets.gen_publish("subpub/qos2/receive/maximum2", qos=2, mid=mid, payload="message3", proto_ver=5)
    pubrec_packet3 = mqtt_packets.gen_pubrec(mid, proto_ver=5)
    pubrel_packet3 = mqtt_packets.gen_pubrel(mid, proto_ver=5)
    pubcomp_packet3 = mqtt_packets.gen_pubcomp(mid, proto_ver=5)


    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)

    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        helper(port)

        mosq_test.expect_packet(sock, "publish1", publish_packet1)
        mosq_test.expect_packet(sock, "publish2", publish_packet2)
        mosq_test.do_send_receive(sock, pubrec_packet1, pubrel_packet1, "pubrel1")
        sock.send(pubcomp_packet1)

        mosq_test.expect_packet(sock, "publish3", publish_packet3)
        mosq_test.do_send_receive(sock, pubrec_packet2, pubrel_packet2, "pubrel2")
        sock.send(pubcomp_packet2)

        mosq_test.do_send_receive(sock, pubrec_packet3, pubrel_packet3, "pubrel3")
        sock.send(pubcomp_packet3)
        sock.close()


if __name__ == '__main__':
    do_test(proto_ver=5)
