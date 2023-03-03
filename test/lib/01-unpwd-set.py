#!/usr/bin/env python3

# Test whether a client produces a correct connect with a username and password.

# The client should connect to port 1888 with keepalive=60, clean session set,
# client id 01-unpwd-set, username set to uname and password set to ;'[08gn=#

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("01-unpwd-set", username="uname", password=";'[08gn=#")

    mosq_test.expect_packet(conn, "connect", connect_packet)


mosq_test.client_test("c/01-unpwd-set.test", [], do_test, None)
mosq_test.client_test("cpp/01-unpwd-set.test", [], do_test, None)
