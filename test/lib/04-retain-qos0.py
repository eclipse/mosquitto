#!/usr/bin/env python3

# Test whether a client sends a correct retained PUBLISH to a topic with QoS 0.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("retain-qos0-test")
    connack_packet = mosq_test.gen_connack(rc=0)

    mid = 16
    publish_packet = mosq_test.gen_publish("retain/qos0/test", qos=0, payload="retained message", retain=True)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

    mosq_test.expect_packet(conn, "publish", publish_packet)

    conn.close()


mosq_test.client_test("c/04-retain-qos0.test", [], do_test, None)
mosq_test.client_test("cpp/04-retain-qos0.test", [], do_test, None)
