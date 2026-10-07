#!/usr/bin/env python3

# Test whether a client produces a correct connect and subsequent disconnect.

# The client should connect to port 1888 with keepalive=60, clean session set,
# and client id 01-con-discon-success
# The test will send a CONNACK message to the client with rc=0. Upon receiving
# the CONNACK and verifying that rc=0, the client should send a DISCONNECT
# message. If rc!=0, the client should exit with an error.

from mosq_test_helper import *

def do_test(conn, data):
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.MAXIMUM_PACKET_SIZE, 1000)
    props += mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 20)
    connect_packet = mqtt_packets.gen_connect("01-con-discon-success-v5", proto_ver=5, properties=props)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "01-con-discon-success-v5.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "01-con-discon-success-v5.exe"), [], do_test, None)
