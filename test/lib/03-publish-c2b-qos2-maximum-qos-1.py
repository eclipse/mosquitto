#!/usr/bin/env python3

# Test whether a client correctly handles sending a message with QoS > maximum QoS.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("publish-qos2-test", proto_ver=5)

    props = mqtt5_props.gen_byte_prop(mqtt5_props.PROP_MAXIMUM_QOS, 1)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props)

    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5)

    mid = 1
    publish_1_packet = mosq_test.gen_publish("maximum/qos/qos1", qos=1, mid=mid, payload="message", proto_ver=5)
    puback_1_packet = mosq_test.gen_puback(mid, proto_ver=5)

    publish_2_packet = mosq_test.gen_publish("maximum/qos/qos0", qos=0, payload="message", proto_ver=5)

    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_receive_send(conn, publish_1_packet, puback_1_packet, "publish 1")

    mosq_test.expect_packet(conn, "publish 2", publish_2_packet)
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)

    conn.close()


mosq_test.client_test("c/03-publish-c2b-qos2-maximum-qos-1.test", [], do_test, None)
mosq_test.client_test("cpp/03-publish-c2b-qos2-maximum-qos-1.test", [], do_test, None)
