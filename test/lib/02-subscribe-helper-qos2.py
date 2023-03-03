#!/usr/bin/env python3

# Test whether a client sends a correct SUBSCRIBE to a topic with QoS 2.

# The client should connect to port 1888 with keepalive=60, clean session set,
# and client id subscribe-qos2-test
# The test will send a CONNACK message to the client with rc=0. Upon receiving
# the CONNACK and verifying that rc=0, the client should send a SUBSCRIBE
# message to subscribe to topic "qos2/test" with QoS=2. If rc!=0, the client
# should exit with an error.
# Upon receiving the correct SUBSCRIBE message, the test will reply with a
# SUBACK message with the accepted QoS set to 2. On receiving the SUBACK
# message, the client should send a DISCONNECT message.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("subscribe-qos2-test")
    connack_packet = mosq_test.gen_connack(rc=0)

    disconnect_packet = mosq_test.gen_disconnect()

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "qos2/test", 2)
    suback_packet = mosq_test.gen_suback(mid, 2)

    publish_packet = mosq_test.gen_publish("qos2/test", 0, "message")

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_receive_send(conn, subscribe_packet, suback_packet, "subscribe")
    conn.send(publish_packet)
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


mosq_test.client_test("c/02-subscribe-helper-simple-qos2.test", [], do_test, None)
mosq_test.client_test("cpp/02-subscribe-helper-simple-qos2.test", [], do_test, None)
mosq_test.client_test("c/02-subscribe-helper-callback-qos2.test", [], do_test, None)
mosq_test.client_test("cpp/02-subscribe-helper-callback-qos2.test", [], do_test, None)
