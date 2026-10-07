#!/usr/bin/env python3

# Check whether a v5 client handles a v5 PUBREC, PUBCOMP with all combinations
# of with/without reason code and properties.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mqtt_packets.gen_connect("publish-qos2-test", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5)

    publish_packet = mqtt_packets.gen_publish("pub/qos2/test", qos=2, mid=data['mid'], payload="message", proto_ver=5)
    pubrel_packet = mqtt_packets.gen_pubrel(data['mid'], proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_receive_send(conn, publish_packet, data['pubrec_packet'], "publish")
    mosq_test.do_receive_send(conn, pubrel_packet, data['pubcomp_packet'], "pubrel")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


data = {}
data['mid'] = 1
# No reason code, no properties
data['pubrec_packet'] = mqtt_packets.gen_pubrec(data['mid'])
data['pubcomp_packet'] = mqtt_packets.gen_pubcomp(data['mid'])
mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-c2b-qos2-len.exe"), [], do_test, data)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-c2b-qos2-len.exe"), [], do_test, data)

# Reason code, no properties
data['pubrec_packet'] = mqtt_packets.gen_pubrec(data['mid'], proto_ver=5, reason_code=0x00)
data['pubcomp_packet'] = mqtt_packets.gen_pubcomp(data['mid'], proto_ver=5, reason_code=0x00)
mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-c2b-qos2-len.exe"), [], do_test, data)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-c2b-qos2-len.exe"), [], do_test, data)

# Reason code, empty properties
data['pubrec_packet'] = mqtt_packets.gen_pubrec(data['mid'], proto_ver=5, reason_code=0x00, properties="")
data['pubcomp_packet'] = mqtt_packets.gen_pubcomp(data['mid'], proto_ver=5, reason_code=0x00, properties="")
mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-c2b-qos2-len.exe"), [], do_test, data)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-c2b-qos2-len.exe"), [], do_test, data)

# Reason code, one property
props = mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "key", "value")
data['pubrec_packet'] = mqtt_packets.gen_pubrec(data['mid'], proto_ver=5, reason_code=0x00, properties=props)
props = mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "key", "value")
data['pubcomp_packet'] = mqtt_packets.gen_pubcomp(data['mid'], proto_ver=5, reason_code=0x00, properties=props)
mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-c2b-qos2-len.exe"), [], do_test, data)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-c2b-qos2-len.exe"), [], do_test, data)
