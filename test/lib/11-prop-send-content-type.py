#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mqtt_packets.gen_connect("prop-test", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    props = mqtt5_props.gen_string_prop(mqtt5_props.CONTENT_TYPE, "application/json")
    publish_packet = mqtt_packets.gen_publish("prop/qos0", qos=0, payload="message", proto_ver=5, properties=props)

    disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

    mosq_test.expect_packet(conn, "publish", publish_packet)
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)

    conn.close()


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "11-prop-send-content-type.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "11-prop-send-content-type.exe"), [], do_test, None)
