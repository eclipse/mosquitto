#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("prop-test", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_CONTENT_TYPE, "application/json")
    publish_packet = mosq_test.gen_publish("prop/qos0", qos=0, payload="message", proto_ver=5, properties=props)

    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

    mosq_test.expect_packet(conn, "publish", publish_packet)
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)

    conn.close()


mosq_test.client_test("c/11-prop-send-content-type.test", [], do_test, None)
mosq_test.client_test("cpp/11-prop-send-content-type.test", [], do_test, None)
