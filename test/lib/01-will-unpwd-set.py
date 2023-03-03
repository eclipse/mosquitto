#!/usr/bin/env python3

# Test whether a client produces a correct connect with a will, username and password.

# The client should connect to port 1888 with keepalive=60, clean session set,
# client id 01-will-unpwd-set , will topic set to "will-topic", will payload
# set to "will message", will qos=2, will retain not set, username set to
# "oibvvwqw" and password set to "#'^2hg9a&nm38*us".

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("01-will-unpwd-set",
            username="oibvvwqw", password="#'^2hg9a&nm38*us",
            will_topic="will-topic", will_qos=2, will_payload=b"will message")

    mosq_test.expect_packet(conn, "connect", connect_packet)


mosq_test.client_test("c/01-will-unpwd-set.test", [], do_test, None)
mosq_test.client_test("cpp/01-will-unpwd-set.test", [], do_test, None)
