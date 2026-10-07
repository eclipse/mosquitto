#!/usr/bin/env python3

# Check whether the broker handles a v5 PUBREC, PUBCOMP with all combinations
# of with/without reason code and properties.

from mosq_test_helper import *

def helper(port):
    connect_packet = mqtt_packets.gen_connect("03-b2c-qos2-len-helper")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    mid = 1
    publish_packet = mqtt_packets.gen_publish("03/b2c/qos2/len/test", qos=2, mid=mid, payload="len-message")
    pubrec_packet = mqtt_packets.gen_pubrec(mid)
    pubrel_packet = mqtt_packets.gen_pubrel(mid)
    pubcomp_packet = mqtt_packets.gen_pubcomp(mid)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, connack_error="helper connack", port=port)

    mosq_test.do_send_receive(sock, publish_packet, pubrec_packet, "helper pubrec")
    mosq_test.do_send_receive(sock, pubrel_packet, pubcomp_packet, "helper pubcomp")
    sock.close()


def do_test(test, pubrec_packet, pubcomp_packet):
    mid = 3265
    connect_packet = mqtt_packets.gen_connect("03-b2c-qos2-len-test", clean_session=False, proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(flags=0, rc=0, proto_ver=5)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "03/b2c/qos2/len/test", 2, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid, 2, proto_ver=5)

    mid = 1
    publish_packet = mqtt_packets.gen_publish("03/b2c/qos2/len/test", qos=2, mid=mid, payload="len-message", proto_ver=5)
    pubrel_packet = mqtt_packets.gen_pubrel(mid)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)

    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        helper(port)
        # Should have now received a publish command

        mosq_test.expect_packet(sock, "publish", publish_packet)
        mosq_test.do_send_receive(sock, pubrec_packet, pubrel_packet, "pubrel")
        sock.send(pubcomp_packet)

        mosq_test.do_ping(sock)
        sock.close()


if __name__ == '__main__':
    # No reason code, no properties
    pubrec_packet = mqtt_packets.gen_pubrec(1)
    pubcomp_packet = mqtt_packets.gen_pubcomp(1)
    do_test("qos2 len 2", pubrec_packet, pubcomp_packet)

    # Reason code, no properties
    pubrec_packet = mqtt_packets.gen_pubrec(1, proto_ver=5, reason_code=0x00)
    pubcomp_packet = mqtt_packets.gen_pubcomp(1, proto_ver=5, reason_code=0x00)
    do_test("qos2 len 3", pubrec_packet, pubcomp_packet)

    # Reason code, empty properties
    pubrec_packet = mqtt_packets.gen_pubrec(1, proto_ver=5, reason_code=0x00, properties="")
    pubcomp_packet = mqtt_packets.gen_pubcomp(1, proto_ver=5, reason_code=0x00, properties="")
    do_test("qos2 len 4", pubrec_packet, pubcomp_packet)

    # Reason code, one property
    props = mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "key", "value")
    pubrec_packet = mqtt_packets.gen_pubrec(1, proto_ver=5, reason_code=0x00, properties=props)
    props = mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "key", "value")
    pubcomp_packet = mqtt_packets.gen_pubcomp(1, proto_ver=5, reason_code=0x00, properties=props)
    do_test("qos2 len >5", pubrec_packet, pubcomp_packet)
