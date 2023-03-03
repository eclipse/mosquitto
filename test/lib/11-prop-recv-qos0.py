#!/usr/bin/env python3

# Check whether the v5 message callback gets the properties

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("prop-test", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_CONTENT_TYPE, "plain/text")
    props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_RESPONSE_TOPIC, "msg/123")
    publish_packet = mosq_test.gen_publish("prop/test", qos=0, payload="message", proto_ver=5, properties=props)

    ok_packet = mosq_test.gen_publish("ok", qos=0, payload="ok", proto_ver=5)

    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_send_receive(conn, publish_packet, ok_packet, "ok")

    conn.close()


mosq_test.client_test("c/11-prop-recv.test", ["0"], do_test, None)
mosq_test.client_test("cpp/11-prop-recv.test", ["0"], do_test, None)
