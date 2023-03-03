#!/usr/bin/env python3

# Test whether a client responds correctly to multiple PUBLISH with QoS 1, with
# receive maximum set to 3.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("publish-qos1-test", proto_ver=5)

    props = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_RECEIVE_MAXIMUM, 3)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props, property_helper=False)

    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5)

    mid = 1
    publish_1_packet = mosq_test.gen_publish("topic", qos=1, mid=mid, payload="12345", proto_ver=5)
    puback_1_packet = mosq_test.gen_puback(mid, proto_ver=5)

    mid = 2
    publish_2_packet = mosq_test.gen_publish("topic", qos=1, mid=mid, payload="12345", proto_ver=5)
    puback_2_packet = mosq_test.gen_puback(mid, proto_ver=5)

    mid = 3
    publish_3_packet = mosq_test.gen_publish("topic", qos=1, mid=mid, payload="12345", proto_ver=5)
    puback_3_packet = mosq_test.gen_puback(mid, proto_ver=5)

    mid = 4
    publish_4_packet = mosq_test.gen_publish("topic", qos=1, mid=mid, payload="12345", proto_ver=5)
    puback_4_packet = mosq_test.gen_puback(mid, proto_ver=5)

    mid = 5
    publish_5_packet = mosq_test.gen_publish("topic", qos=1, mid=mid, payload="12345", proto_ver=5)
    puback_5_packet = mosq_test.gen_puback(mid, proto_ver=5)

    mid = 6
    publish_6_packet = mosq_test.gen_publish("topic", qos=1, mid=mid, payload="12345", proto_ver=5)
    puback_6_packet = mosq_test.gen_puback(mid, proto_ver=5)


    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

    mosq_test.expect_packet(conn, "publish 1", publish_1_packet)
    mosq_test.expect_packet(conn, "publish 2", publish_2_packet)
    mosq_test.expect_packet(conn, "publish 3", publish_3_packet)
    conn.send(puback_1_packet)
    conn.send(puback_2_packet)

    mosq_test.expect_packet(conn, "publish 4", publish_4_packet)
    mosq_test.expect_packet(conn, "publish 5", publish_5_packet)
    conn.send(puback_3_packet)

    mosq_test.expect_packet(conn, "publish 6", publish_6_packet)
    conn.send(puback_4_packet)
    conn.send(puback_5_packet)
    conn.send(puback_6_packet)


mosq_test.client_test("c/03-publish-c2b-qos1-receive-maximum.test", [], do_test, None)
mosq_test.client_test("cpp/03-publish-c2b-qos1-receive-maximum.test", [], do_test, None)
