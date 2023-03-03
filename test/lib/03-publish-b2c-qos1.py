#!/usr/bin/env python3

# Test whether a client responds correctly to a PUBLISH with QoS 1.

# The client should connect to port 1888 with keepalive=60, clean session set,
# and client id publish-qos1-test
# The test will send a CONNACK message to the client with rc=0. Upon receiving
# the CONNACK the client should verify that rc==0.
# The test will send the client a PUBLISH message with topic
# "pub/qos1/receive", payload of "message", QoS=1 and mid=123. The client
# should handle this as per the spec by sending a PUBACK message.
# The client should then exit with return code==0.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("publish-qos1-test")
    connack_packet = mosq_test.gen_connack(rc=0)

    disconnect_packet = mosq_test.gen_disconnect()

    mid = 123
    publish_packet = mosq_test.gen_publish("pub/qos1/receive", qos=1, mid=mid, payload="message")
    puback_packet = mosq_test.gen_puback(mid)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_send_receive(conn, publish_packet, puback_packet, "puback")


mosq_test.client_test("c/03-publish-b2c-qos1.test", [], do_test, None)
mosq_test.client_test("cpp/03-publish-b2c-qos1.test", [], do_test, None)
