#!/usr/bin/env python3

# After PUBREC on an outgoing QoS 2 delivery, Message Expiry Interval must not
# delete the owed PUBREL (MQTT-3.3.2.3.3 / MQTT-4.4.0-1). See #3744.

from mosq_test_helper import *


def helper(port, expiry):
    connect_packet = mqtt_packets.gen_connect("03-b2c-qos2-exp-helper", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    mid = 7
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.MESSAGE_EXPIRY_INTERVAL, expiry)
    publish_packet = mqtt_packets.gen_publish(
        "03/b2c/qos2/expiry/inflight", qos=2, mid=mid, payload="inflight",
        proto_ver=5, properties=props)
    pubrec_packet = mqtt_packets.gen_pubrec(mid, proto_ver=5)
    pubrel_packet = mqtt_packets.gen_pubrel(mid, proto_ver=5)
    pubcomp_packet = mqtt_packets.gen_pubcomp(mid, proto_ver=5)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.do_send_receive(sock, publish_packet, pubrec_packet, "helper pubrec")
    mosq_test.do_send_receive(sock, pubrel_packet, pubcomp_packet, "helper pubcomp")
    sock.close()


def do_test():
    mid = 1
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.SESSION_EXPIRY_INTERVAL, 60)
    connect_packet = mqtt_packets.gen_connect(
        "03-b2c-qos2-exp-sub", clean_session=False, proto_ver=5, properties=props)
    connack1_packet = mqtt_packets.gen_connack(flags=0, rc=0, proto_ver=5)
    connack2_packet = mqtt_packets.gen_connack(flags=1, rc=0, proto_ver=5)

    subscribe_packet = mqtt_packets.gen_subscribe(
        mid, "03/b2c/qos2/expiry/inflight", 2, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid, 2, proto_ver=5)

    mid = 1
    publish_packet = mqtt_packets.gen_publish(
        "03/b2c/qos2/expiry/inflight", qos=2, mid=mid, payload="inflight", proto_ver=5)
    pubrec_packet = mqtt_packets.gen_pubrec(mid, proto_ver=5)
    pubrel_packet = mqtt_packets.gen_pubrel(mid, proto_ver=5)
    pubcomp_packet = mqtt_packets.gen_pubcomp(mid, proto_ver=5)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack1_packet, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        helper(port, expiry=2)
        # Broker forwards Message Expiry Interval; accept remaining 1 or 2.
        matched = False
        packet = sock.recv(200)
        for rem in (2, 1):
            props = mqtt5_props.gen_uint32_prop(mqtt5_props.MESSAGE_EXPIRY_INTERVAL, rem)
            expected = mqtt_packets.gen_publish(
                "03/b2c/qos2/expiry/inflight", qos=2, mid=mid, payload="inflight",
                proto_ver=5, properties=props)
            if packet == expected:
                matched = True
                break
        assert matched, "unexpected publish before PUBREC: %r" % (packet,)
        sock.send(pubrec_packet)
        sock.close()

        # Past Message Expiry Interval; session itself must still be present.
        time.sleep(4)

        sock = mosq_test.do_client_connect(connect_packet, connack2_packet, port=port)
        mosq_test.expect_packet(sock, "pubrel after expiry", pubrel_packet)
        sock.send(pubcomp_packet)
        sock.close()


do_test()
