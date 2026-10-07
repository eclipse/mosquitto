#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mqtt_packets.gen_connect("publish-qos2-test")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    disconnect_packet = mqtt_packets.gen_disconnect()

    pubrel_unexpected = mqtt_packets.gen_pubrel(1000)
    pubcomp_unexpected = mqtt_packets.gen_pubcomp(1000)

    mid = 13423
    publish_packet = mqtt_packets.gen_publish("pub/qos2/receive", qos=2, mid=mid, payload="message")
    pubrec_packet = mqtt_packets.gen_pubrec(mid)
    pubrel_packet = mqtt_packets.gen_pubrel(mid)
    pubcomp_packet = mqtt_packets.gen_pubcomp(mid)

    publish_quit_packet = mqtt_packets.gen_publish("quit", qos=0, payload="quit")

    mosq_test.expect_packet(conn, "connect", connect_packet)
    conn.send(connack_packet)

    conn.send(pubrel_unexpected)
    mosq_test.expect_packet(conn, "pubcomp", pubcomp_unexpected)

    conn.send(publish_packet)

    mosq_test.expect_packet(conn, "pubrec", pubrec_packet)
    conn.send(pubrel_packet)

    mosq_test.expect_packet(conn, "pubcomp", pubcomp_packet)
    conn.send(publish_quit_packet)
    conn.close()


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-b2c-qos2-unexpected-pubrel.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-b2c-qos2-unexpected-pubrel.exe"), [], do_test, None)
