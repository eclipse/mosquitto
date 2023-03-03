#!/usr/bin/env python3

# Test whether a client sends a correct SUBSCRIBE to a topic with QoS 1.

# The client should connect to port 1888 with keepalive=60, clean session set,
# and client id subscribe-qos1-test
# The test will send a CONNACK message to the client with rc=0. Upon receiving
# the CONNACK and verifying that rc=0, the client should send a SUBSCRIBE
# message to subscribe to topic "qos1/test" with QoS=1. If rc!=0, the client
# should exit with an error.
# Upon receiving the correct SUBSCRIBE message, the test will reply with a
# SUBACK message with the accepted QoS set to 1. On receiving the SUBACK
# message, the client should send a DISCONNECT message.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("subscribe-qos1-test")
    connack_packet = mosq_test.gen_connack(rc=0)

    disconnect_packet = mosq_test.gen_disconnect()

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "qos1/test", 1)
    suback_packet = mosq_test.gen_suback(mid, 1)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_receive_send(conn, subscribe_packet, suback_packet, "subscribe")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


mosq_test.client_test("c/02-subscribe-qos1.test", [], do_test, None)
mosq_test.client_test("c/02-subscribe-qos1-async1.test", [], do_test, None)
mosq_test.client_test("c/02-subscribe-qos1-async2.test", [], do_test, None)
mosq_test.client_test("cpp/02-subscribe-qos1.test", [], do_test, None)
mosq_test.client_test("cpp/02-subscribe-qos1-async1.test", [], do_test, None)
# FIXME - CI fails here, connection refused mosq_test.client_test("cpp/02-subscribe-qos1-async2.test", [], do_test, None)
