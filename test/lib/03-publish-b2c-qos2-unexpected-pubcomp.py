#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(conn, data):
    keepalive = 2
    connect_packet = mqtt_packets.gen_connect("publish-qos2-test", keepalive=keepalive)
    connack_packet = mqtt_packets.gen_connack(rc=0)

    disconnect_packet = mqtt_packets.gen_disconnect()

    mid = 13423
    pubcomp_packet = mqtt_packets.gen_pubcomp(mid)
    pingreq_packet = mqtt_packets.gen_pingreq()

    mosq_test.expect_packet(conn, "connect", connect_packet)
    conn.send(connack_packet)
    conn.send(pubcomp_packet)

    mosq_test.expect_packet(conn, "pingreq", pingreq_packet)


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-b2c-qos2-unexpected-pubcomp.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-b2c-qos2-unexpected-pubcomp.exe"), [], do_test, None)
