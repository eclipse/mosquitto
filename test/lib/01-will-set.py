#!/usr/bin/env python3

# Test whether a client produces a correct connect with a will.
# Will QoS=1, will retain=1.

# The client should connect to port 1888 with keepalive=60, clean session set,
# client id 01-will-set will topic set to topic/on/unexpected/disconnect , will
# payload set to "will message", will qos set to 1 and will retain set.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("01-will-set", will_topic="topic/on/unexpected/disconnect", will_qos=1, will_retain=True, will_payload=b"will message")

    mosq_test.expect_packet(conn, "connect", connect_packet)


mosq_test.client_test("c/01-will-set.test", [], do_test, None)
mosq_test.client_test("cpp/01-will-set.test", [], do_test, None)
