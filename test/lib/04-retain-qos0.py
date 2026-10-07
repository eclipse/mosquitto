#!/usr/bin/env python3

# Test whether a client sends a correct retained PUBLISH to a topic with QoS 0.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mqtt_packets.gen_connect("retain-qos0-test")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    mid = 16
    publish_packet = mqtt_packets.gen_publish("retain/qos0/test", qos=0, payload="retained message", retain=True)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

    mosq_test.expect_packet(conn, "publish", publish_packet)

    conn.close()


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "04-retain-qos0.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "04-retain-qos0.exe"), [], do_test, None)
