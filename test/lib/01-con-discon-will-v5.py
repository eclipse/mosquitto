#!/usr/bin/env python3

# Test whether a client produces a correct connect and subsequent disconnect, with a will, MQTT v5

from mosq_test_helper import *

def do_test(conn, data):
    props = mqtt5_props.gen_byte_prop(mqtt5_props.PROP_PAYLOAD_FORMAT_INDICATOR, 0x01)
    connect_packet = mosq_test.gen_connect("01-con-discon-will", will_topic="will/topic", will_payload=b"will-payload", will_qos=1, will_retain=True, will_properties=props, proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)
    disconnect_packet = mosq_test.gen_disconnect()

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


mosq_test.client_test("c/01-con-discon-will-v5.test", [], do_test, None)
mosq_test.client_test("cpp/01-con-discon-will-v5.test", [], do_test, None)
