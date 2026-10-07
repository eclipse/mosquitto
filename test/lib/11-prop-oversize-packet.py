#!/usr/bin/env python3

# Test whether a client publishing an oversize packet correctly.
# The client should try to publish a message that is too big, then the one below which is ok.
# It should also try to subscribe with a too large topic

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mqtt_packets.gen_connect("publish-qos0-test", proto_ver=5)
    props = mqtt5_props.gen_uint16_prop(mqtt5_props.TOPIC_ALIAS_MAXIMUM, 10)
    props += mqtt5_props.gen_uint32_prop(mqtt5_props.MAXIMUM_PACKET_SIZE, 30)
    props += mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 20)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5, properties=props, property_helper=False)

    bad_publish_packet = mqtt_packets.gen_publish("pub/test", qos=0, payload="123456789012345678", proto_ver=5)
    publish_packet = mqtt_packets.gen_publish("pub/test", qos=0, payload="12345678901234567", proto_ver=5)

    disconnect_packet = mqtt_packets.gen_disconnect()

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

    mosq_test.expect_packet(conn, "publish", publish_packet)
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)

    conn.close()


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "11-prop-oversize-packet.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "11-prop-oversize-packet.exe"), [], do_test, None)
