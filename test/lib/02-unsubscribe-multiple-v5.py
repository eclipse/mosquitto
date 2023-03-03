#!/usr/bin/env python3

# Test whether a v5 client sends a correct UNSUBSCRIBE packet with multiple
# topics, and handles the UNSUBACK.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("unsubscribe-test", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "unsubscribe/test", 2, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 2, proto_ver=5)

    mid = 2
    unsubscribe_packet = mosq_test.gen_unsubscribe_multiple(mid, ["unsubscribe/test", "no-sub"], proto_ver=5)
    unsuback_packet = mosq_test.gen_unsuback(mid, reason_code=[0, 17], proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_receive_send(conn, subscribe_packet, suback_packet, "subscribe")
    mosq_test.do_receive_send(conn, unsubscribe_packet, unsuback_packet, "unsubscribe")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


mosq_test.client_test("c/02-unsubscribe-multiple-v5.test", [], do_test, None)
# FIXME - missing func in lib mosq_test.client_test("cpp/02-unsubscribe-multiple-v5.test", [], do_test, None)
