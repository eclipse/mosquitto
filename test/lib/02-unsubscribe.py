#!/usr/bin/env python3

# Test whether a client sends a correct UNSUBSCRIBE packet.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mqtt_packets.gen_connect("unsubscribe-test")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    disconnect_packet = mqtt_packets.gen_disconnect()

    mid = 1
    unsubscribe_packet = mqtt_packets.gen_unsubscribe(mid, "unsubscribe/test")
    unsuback_packet = mqtt_packets.gen_unsuback(mid)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_receive_send(conn, unsubscribe_packet, unsuback_packet, "unsubscribe")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "02-unsubscribe.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "02-unsubscribe.exe"), [], do_test, None)
