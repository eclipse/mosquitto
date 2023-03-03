#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("publish-qos2-test")
    connack_packet = mosq_test.gen_connack(rc=0)

    disconnect_packet = mosq_test.gen_disconnect()

    pubrel_unexpected = mosq_test.gen_pubrel(1000)
    pubcomp_unexpected = mosq_test.gen_pubcomp(1000)

    mid = 13423
    publish_packet = mosq_test.gen_publish("pub/qos2/receive", qos=2, mid=mid, payload="message")
    pubrec_packet = mosq_test.gen_pubrec(mid)
    pubrel_packet = mosq_test.gen_pubrel(mid)
    pubcomp_packet = mosq_test.gen_pubcomp(mid)

    publish_quit_packet = mosq_test.gen_publish("quit", qos=0, payload="quit")

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


mosq_test.client_test("c/03-publish-b2c-qos2-unexpected-pubrel.test", [], do_test, None)
mosq_test.client_test("cpp/03-publish-b2c-qos2-unexpected-pubrel.test", [], do_test, None)
