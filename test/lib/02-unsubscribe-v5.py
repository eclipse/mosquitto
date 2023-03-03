#!/usr/bin/env python3

# Test whether a v5 client sends a correct UNSUBSCRIBE packet, and handles the UNSUBACK.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("unsubscribe-test", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5)

    mid = 1
    props = mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "key", "value")
    unsubscribe_packet = mosq_test.gen_unsubscribe(mid, "unsubscribe/test", proto_ver=5, properties=props)
    unsuback_packet = mosq_test.gen_unsuback(mid, proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_receive_send(conn, unsubscribe_packet, unsuback_packet, "unsubscribe")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


mosq_test.client_test("c/02-unsubscribe-v5.test", [], do_test, None)
mosq_test.client_test("cpp/02-unsubscribe-v5.test", [], do_test, None)
# FIXME - missing lib function mosq_test.client_test("c/02-unsubscribe2-v5.test", [], do_test, None)
# FIXME - missing lib function mosq_test.client_test("cpp/02-unsubscribe2-v5.test", [], do_test, None)
