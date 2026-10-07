#!/usr/bin/env python3

# Test whether a client produces a correct connect and subsequent disconnect, with a will.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mqtt_packets.gen_connect("01-con-discon-will", will_topic="will/topic", will_payload=b"will-payload", will_qos=1, will_retain=True)
    connack_packet = mqtt_packets.gen_connack(rc=0)
    disconnect_packet = mqtt_packets.gen_disconnect()

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "01-con-discon-will.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "01-con-discon-will.exe"), [], do_test, None)
