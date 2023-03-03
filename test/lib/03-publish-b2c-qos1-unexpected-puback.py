#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(conn, data):
    keepalive = 5
    connect_packet = mosq_test.gen_connect("publish-qos1-test", keepalive=keepalive)
    connack_packet = mosq_test.gen_connack(rc=0)

    disconnect_packet = mosq_test.gen_disconnect()

    mid = 13423
    puback_packet = mosq_test.gen_puback(mid)
    pingreq_packet = mosq_test.gen_pingreq()

    mosq_test.expect_packet(conn, "connect", connect_packet)
    conn.send(connack_packet)
    conn.send(puback_packet)

    mosq_test.expect_packet(conn, "pingreq", pingreq_packet)


mosq_test.client_test("c/03-publish-b2c-qos1-unexpected-puback.test", [], do_test, None)
mosq_test.client_test("cpp/03-publish-b2c-qos1-unexpected-puback.test", [], do_test, None)
