#!/usr/bin/env python3

# Check whether the v5 message callback gets the properties

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mosq_test.gen_connect("prop-test", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 1
    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_CONTENT_TYPE, "plain/text")
    props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_RESPONSE_TOPIC, "msg/123")
    publish_packet = mosq_test.gen_publish("prop/test", mid=mid, qos=2, payload="message", proto_ver=5, properties=props)
    pubrec_packet = mosq_test.gen_pubrec(mid=mid, proto_ver=5)
    pubrel_packet = mosq_test.gen_pubrel(mid=mid, proto_ver=5)
    pubcomp_packet = mosq_test.gen_pubcomp(mid=mid, proto_ver=5)

    ok_packet = mosq_test.gen_publish("ok", qos=0, payload="ok", proto_ver=5)

    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_send_receive(conn, publish_packet, pubrec_packet, "pubrec")
    mosq_test.do_send_receive(conn, pubrel_packet, pubcomp_packet, "pubcomp")
    mosq_test.expect_packet(conn, "ok", ok_packet)

    conn.close()


mosq_test.client_test("c/11-prop-recv.test", ["2"], do_test, None)
mosq_test.client_test("cpp/11-prop-recv.test", ["2"], do_test, None)
