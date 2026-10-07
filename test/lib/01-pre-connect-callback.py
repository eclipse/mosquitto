#!/usr/bin/env python3

# Test whether the pre-connect callback is triggered and allows us to set a username and password.

# The client should connect to port 1888 with keepalive=60, clean session set,
# client id 01-pre-connect, username set to uname and password set to ;'[08gn=#

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mqtt_packets.gen_connect("01-pre-connect", username="uname", password=";'[08gn=#")

    mosq_test.expect_packet(conn, "connect", connect_packet)


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "01-pre-connect-callback.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "01-pre-connect-callback.exe"), [], do_test, None)
