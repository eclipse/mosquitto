#!/usr/bin/env python3

# Test whether a client sends a pingreq after the keepalive time

# The client should connect to port 1888 with keepalive=4, clean session set,
# and client id 01-keepalive-pingreq
# The client should send a PINGREQ message after the appropriate amount of time
# (4 seconds after no traffic).

from mosq_test_helper import *

def do_test(conn, data):
    keepalive = 5
    connect_packet = mosq_test.gen_connect("01-keepalive-pingreq", keepalive=keepalive)
    connack_packet = mosq_test.gen_connack(rc=0)

    pingreq_packet = mosq_test.gen_pingreq()
    pingresp_packet = mosq_test.gen_pingresp()

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

    mosq_test.expect_packet(conn, "pingreq", pingreq_packet)
    time.sleep(1.0)
    conn.send(pingresp_packet)

    mosq_test.expect_packet(conn, "pingreq", pingreq_packet)


mosq_test.client_test("c/01-keepalive-pingreq.test", [], do_test, None)
mosq_test.client_test("cpp/01-keepalive-pingreq.test", [], do_test, None)
