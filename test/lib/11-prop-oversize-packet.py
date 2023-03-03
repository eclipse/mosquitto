#!/usr/bin/env python3

# Test whether a client publishing an oversize packet correctly.
# The client should try to publish a message that is too big, then the one below which is ok.
# It should also try to subscribe with a too large topic

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("publish-qos0-test", proto_ver=5)
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_MAXIMUM_PACKET_SIZE, 30)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props)

    bad_publish_packet = mosq_test.gen_publish("pub/test", qos=0, payload="0123456789012345678", proto_ver=5)
    publish_packet = mosq_test.gen_publish("pub/test", qos=0, payload="012345678901234567", proto_ver=5)

    disconnect_packet = mosq_test.gen_disconnect()

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

    mosq_test.expect_packet(conn, "publish", publish_packet)
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)

    conn.close()


mosq_test.client_test("c/11-prop-oversize-packet.test", [], do_test, None)
mosq_test.client_test("cpp/11-prop-oversize-packet.test", [], do_test, None)
