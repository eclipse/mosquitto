#!/usr/bin/env python3

from mosq_test_helper import *
import mqtt5_rc

def do_test(conn, data):
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.MAXIMUM_PACKET_SIZE, 1000)
    props += mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 20)
    connect_packet = mqtt_packets.gen_connect("01-extended-auth", proto_ver=5, properties=props)

    props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "test-method")
    props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "test-request") # This is really a binary property
    auth_continue_b2c = mqtt_packets.gen_auth(reason_code=mqtt5_rc.CONTINUE_AUTHENTICATION, properties=props)

    props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "test-method")
    props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "test-reply") # This is really a binary property
    auth_continue_c2b = mqtt_packets.gen_auth(reason_code=mqtt5_rc.CONTINUE_AUTHENTICATION, properties=props)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, auth_continue_b2c, "auth_b2c")
    mosq_test.do_receive_send(conn, auth_continue_c2b, connack_packet, "connack")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "01-extended-auth-continue.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "01-extended-auth-continue.exe"), [], do_test, None)
