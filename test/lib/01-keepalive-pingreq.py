#!/usr/bin/env python3

# Test whether a client sends a pingreq after the keepalive time

# The client should connect to port 1888 with keepalive=4, clean session set,
# and client id 01-keepalive-pingreq
# The client should send a PINGREQ message after the appropriate amount of time
# (4 seconds after no traffic).

from mosq_test_helper import *

def do_test(conn, data):
    keepalive = 2
    connect_packet = mqtt_packets.gen_connect("01-keepalive-pingreq", keepalive=keepalive)
    connack_packet = mqtt_packets.gen_connack(rc=0)

    pingreq_packet = mqtt_packets.gen_pingreq()
    pingresp_packet = mqtt_packets.gen_pingresp()

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

    mosq_test.expect_packet(conn, "pingreq", pingreq_packet)
    conn.send(pingresp_packet)

    mosq_test.expect_packet(conn, "pingreq", pingreq_packet)


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "01-keepalive-pingreq.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "01-keepalive-pingreq.exe"), [], do_test, None)
