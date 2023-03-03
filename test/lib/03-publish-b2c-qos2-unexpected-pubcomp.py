#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(conn, data):
    keepalive = 5
    connect_packet = mosq_test.gen_connect("publish-qos2-test", keepalive=keepalive)
    connack_packet = mosq_test.gen_connack(rc=0)

    disconnect_packet = mosq_test.gen_disconnect()

    mid = 13423
    pubcomp_packet = mosq_test.gen_pubcomp(mid)
    pingreq_packet = mosq_test.gen_pingreq()

    mosq_test.expect_packet(conn, "connect", connect_packet)
    conn.send(connack_packet)
    conn.send(pubcomp_packet)

    mosq_test.expect_packet(conn, "pingreq", pingreq_packet)


mosq_test.client_test("c/03-publish-b2c-qos2-unexpected-pubcomp.test", [], do_test, None)
mosq_test.client_test("cpp/03-publish-b2c-qos2-unexpected-pubcomp.test", [], do_test, None)
