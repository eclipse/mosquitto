#!/usr/bin/env python3

# Test whether a client sends a correct PUBLISH to a topic with QoS 2.

# The client should connect to port 1888 with keepalive=60, clean session set,
# and client id publish-qos2-test
# The test will send a CONNACK message to the client with rc=0. Upon receiving
# the CONNACK the client should verify that rc==0. If not, it should exit with
# return code=1.
# On a successful CONNACK, the client should send a PUBLISH message with topic
# "pub/qos2/test", payload "message" and QoS=2.
# The test will not respond to the first PUBLISH message, so the client must
# resend the PUBLISH message with dup=1. Note that to keep test durations low, a
# message retry timeout of less than 10 seconds is required for this test.
# On receiving the second PUBLISH message, the test will send the correct
# PUBREC response. On receiving the correct PUBREC response, the client should
# send a PUBREL message.
# The test will not respond to the first PUBREL message, so the client must
# resend the PUBREL message with dup=1. On receiving the second PUBREL message,
# the test will send the correct PUBCOMP response. On receiving the correct
# PUBCOMP response, the client should send a DISCONNECT message.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mqtt_packets.gen_connect("publish-qos2-test")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    disconnect_packet = mqtt_packets.gen_disconnect()

    mid = 1
    publish_packet = mqtt_packets.gen_publish("pub/qos2/test", qos=2, mid=mid, payload="message")
    publish_dup_packet = mqtt_packets.gen_publish("pub/qos2/test", qos=2, mid=mid, payload="message", dup=True)
    pubrec_packet = mqtt_packets.gen_pubrec(mid)
    pubrel_packet = mqtt_packets.gen_pubrel(mid)
    pubcomp_packet = mqtt_packets.gen_pubcomp(mid)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_receive_send(conn, publish_packet, pubrec_packet, "publish")
    mosq_test.do_receive_send(conn, pubrel_packet, pubcomp_packet, "pubrel")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)

    conn.close()


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-c2b-qos2.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-c2b-qos2.exe"), [], do_test, None)
