#!/usr/bin/env python3

# Test whether a v5 client sends a correct UNSUBSCRIBE packet, and handles the UNSUBACK.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mqtt_packets.gen_connect("unsubscribe-test", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5)

    mid = 1
    props = mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "key", "value")
    unsubscribe_packet = mqtt_packets.gen_unsubscribe(mid, "unsubscribe/test", proto_ver=5, properties=props)
    unsuback_packet = mqtt_packets.gen_unsuback(mid, proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_receive_send(conn, unsubscribe_packet, unsuback_packet, "unsubscribe")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "02-unsubscribe-v5.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("c", mosq_test.get_build_type(), "02-unsubscribe-v5.exe"), [], do_test, None)
