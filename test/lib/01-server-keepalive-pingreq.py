#!/usr/bin/env python3

# Test whether a client sends a pingreq after the keepalive time
# Client sets a keepalive of 60 seconds, but receives a server keepalive to set
# it back to 4 seconds.

from mosq_test_helper import *

def do_test(conn, data):
    keepalive = 60
    server_keepalive = 2
    connect_packet = mqtt_packets.gen_connect("01-server-keepalive-pingreq", keepalive=keepalive, proto_ver=5)

    props = mqtt5_props.gen_uint16_prop(mqtt5_props.SERVER_KEEP_ALIVE, server_keepalive)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5, properties=props)

    pingreq_packet = mqtt_packets.gen_pingreq()
    pingresp_packet = mqtt_packets.gen_pingresp()

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

    mosq_test.expect_packet(conn, "pingreq", pingreq_packet)
    conn.send(pingresp_packet)

    mosq_test.expect_packet(conn, "pingreq", pingreq_packet)


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "01-server-keepalive-pingreq.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "01-server-keepalive-pingreq.exe"), [], do_test, None)
