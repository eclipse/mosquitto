#!/usr/bin/env python3

# Test whether the pre-connect callback is triggered and allows us to set a username and password.

# The client should connect to port 1888 with keepalive=60, clean session set,
# client id 01-pre-connect, username set to uname and password set to ;'[08gn=#

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("01-pre-connect", username="uname", password=";'[08gn=#")

    mosq_test.expect_packet(conn, "connect", connect_packet)


mosq_test.client_test("c/01-pre-connect-callback.test", [], do_test, None)
mosq_test.client_test("cpp/01-pre-connect-callback.test", [], do_test, None)
