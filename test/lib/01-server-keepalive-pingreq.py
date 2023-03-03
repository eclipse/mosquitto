#!/usr/bin/env python3

# Test whether a client sends a pingreq after the keepalive time
# Client sets a keepalive of 60 seconds, but receives a server keepalive to set
# it back to 4 seconds.

from mosq_test_helper import *

def do_test(conn, data):
    keepalive = 60
    server_keepalive = 4
    connect_packet = mosq_test.gen_connect("01-server-keepalive-pingreq", keepalive=keepalive, proto_ver=5)

    props = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_SERVER_KEEP_ALIVE, server_keepalive)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props)

    pingreq_packet = mosq_test.gen_pingreq()
    pingresp_packet = mosq_test.gen_pingresp()

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

    mosq_test.expect_packet(conn, "pingreq", pingreq_packet)
    time.sleep(1.0)
    conn.send(pingresp_packet)

    mosq_test.expect_packet(conn, "pingreq", pingreq_packet)


mosq_test.client_test("c/01-server-keepalive-pingreq.test", [], do_test, None)
mosq_test.client_test("cpp/01-server-keepalive-pingreq.test", [], do_test, None)
