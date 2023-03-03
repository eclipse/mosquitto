#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("loop-test", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "loop/test", 0, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5)

    publish_packet = mosq_test.gen_publish("loop/test", qos=0, payload="message", proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_receive_send(conn, subscribe_packet, suback_packet, "subscribe")
    conn.send(publish_packet)
    mosq_test.expect_packet(conn, "publish", publish_packet)
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


mosq_test.client_test("c/03-publish-loop.test", [], do_test, None)
mosq_test.client_test("c/03-publish-loop-forever.test", [], do_test, None)
mosq_test.client_test("c/03-publish-loop-manual.test", [], do_test, None)
mosq_test.client_test("c/03-publish-loop-start.test", [], do_test, None)
mosq_test.client_test("cpp/03-publish-loop.test", [], do_test, None)
mosq_test.client_test("cpp/03-publish-loop-forever.test", [], do_test, None)
mosq_test.client_test("cpp/03-publish-loop-manual.test", [], do_test, None)
mosq_test.client_test("cpp/03-publish-loop-start.test", [], do_test, None)
