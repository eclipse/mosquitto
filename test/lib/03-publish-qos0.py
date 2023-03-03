#!/usr/bin/env python3

# Test whether a client sends a correct PUBLISH to a topic with QoS 0.

# The client should connect to port 1888 with keepalive=60, clean session set,
# and client id publish-qos0-test
# The test will send a CONNACK message to the client with rc=0. Upon receiving
# the CONNACK and verifying that rc=0, the client should send a PUBLISH message
# to topic "pub/qos0/test" with payload "message" and QoS=0. If rc!=0, the
# client should exit with an error.
# After sending the PUBLISH message, the client should send a DISCONNECT message.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("publish-qos0-test")
    connack_packet = mosq_test.gen_connack(rc=0)

    publish_packet = mosq_test.gen_publish("pub/qos0/test", qos=0, payload="message")

    disconnect_packet = mosq_test.gen_disconnect()

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

    mosq_test.expect_packet(conn, "publish", publish_packet)
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)

    conn.close()


mosq_test.client_test("c/03-publish-qos0.test", [], do_test, None)
mosq_test.client_test("cpp/03-publish-qos0.test", [], do_test, None)
