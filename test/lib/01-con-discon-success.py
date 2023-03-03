#!/usr/bin/env python3

# Test whether a client produces a correct connect and subsequent disconnect.

# The client should connect to port 1888 with keepalive=60, clean session set,
# and client id 01-con-discon-success
# The test will send a CONNACK message to the client with rc=0. Upon receiving
# the CONNACK and verifying that rc=0, the client should send a DISCONNECT
# message. If rc!=0, the client should exit with an error.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("01-con-discon-success")
    connack_packet = mosq_test.gen_connack(rc=0)
    disconnect_packet = mosq_test.gen_disconnect()

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)

mosq_test.client_test("c/01-con-discon-success.test", [], do_test, None)
mosq_test.client_test("cpp/01-con-discon-success.test", [], do_test, None)
