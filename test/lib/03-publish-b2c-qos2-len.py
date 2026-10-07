#!/usr/bin/env python3

# Check whether a v5 client handles a v5 PUBREL with all combinations
# of with/without reason code and properties.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mqtt_packets.gen_connect("publish-qos2-test", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5)

    publish_packet = mqtt_packets.gen_publish("len/qos2/test", qos=2, mid=data['mid'], payload="message", proto_ver=5)
    pubrec_packet = mqtt_packets.gen_pubrec(data['mid'], proto_ver=5)
    pubcomp_packet = mqtt_packets.gen_pubcomp(data['mid'], proto_ver=5)

    mosq_test.expect_packet(conn, "connect", connect_packet)
    conn.send(connack_packet)

    mosq_test.do_send_receive(conn, publish_packet, pubrec_packet, "pubrec")
    mosq_test.do_send_receive(conn, data['pubrel_packet'], pubcomp_packet, "pubcomp")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


data = {}
data['mid'] = 56
# No reason code, no properties
data['pubrel_packet'] = mqtt_packets.gen_pubrel(data['mid'])
data['label'] = "qos2 len 2"
mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-b2c-qos2-len.exe"), [], do_test, data)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-b2c-qos2-len.exe"), [], do_test, data)

# Reason code, no properties
data['pubrel_packet'] = mqtt_packets.gen_pubrel(data['mid'], proto_ver=5, reason_code=0x00)
data['label'] = "qos2 len 3"
mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-b2c-qos2-len.exe"), [], do_test, data)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-b2c-qos2-len.exe"), [], do_test, data)

# Reason code, empty properties
data['pubrel_packet'] = mqtt_packets.gen_pubrel(data['mid'], proto_ver=5, reason_code=0x00, properties="")
data['label'] = "qos2 len 4"
mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-b2c-qos2-len.exe"), [], do_test, data)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-b2c-qos2-len.exe"), [], do_test, data)

# Reason code, one property
props = mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "key", "value")
data['pubrel_packet'] = mqtt_packets.gen_pubrel(data['mid'], proto_ver=5, reason_code=0x00, properties=props)
data['label'] = "qos2 len >5"
mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-b2c-qos2-len.exe"), [], do_test, data)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-b2c-qos2-len.exe"), [], do_test, data)
