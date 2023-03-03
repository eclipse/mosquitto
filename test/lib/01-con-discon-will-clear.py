#!/usr/bin/env python3

# Test whether a client produces a correct connect and subsequent disconnect, with setting a will then clearing it.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("01-con-discon-will")
    connack_packet = mosq_test.gen_connack(rc=0)

    disconnect_packet = mosq_test.gen_disconnect()

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


mosq_test.client_test("c/01-con-discon-will-clear.test", [], do_test, None)
mosq_test.client_test("cpp/01-con-discon-will-clear.test", [], do_test, None)
