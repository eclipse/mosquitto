#!/usr/bin/env python3

# Check whether a v5 client handles a v5 PUBACK with all combinations
# of with/without reason code and properties.

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mqtt_packets.gen_connect("publish-qos1-test", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5)

    publish_packet = mqtt_packets.gen_publish("pub/qos1/test", qos=1, mid=data['mid'], payload="message", proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_receive_send(conn, publish_packet, data['puback_packet'], "publish")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


data = {}
data['mid'] = 1
# No reason code, no properties
data['puback_packet'] = mqtt_packets.gen_puback(data['mid'])
data['label'] = "qos1 len 2"
mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-c2b-qos1-len.exe"), [], do_test, data)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-c2b-qos1-len.exe"), [], do_test, data)

# Reason code, no properties
data['puback_packet'] = mqtt_packets.gen_puback(data['mid'], proto_ver=5, reason_code=0x00)
data['label'] = "qos1 len 3"
mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-c2b-qos1-len.exe"), [], do_test, data)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-c2b-qos1-len.exe"), [], do_test, data)

# Reason code, empty properties
data['puback_packet'] = mqtt_packets.gen_puback(data['mid'], proto_ver=5, reason_code=0x00, properties="")
data['label'] = "qos1 len 4"
mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-c2b-qos1-len.exe"), [], do_test, data)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-c2b-qos1-len.exe"), [], do_test, data)

# Reason code, one property
props = mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "key", "value")
data['puback_packet'] = mqtt_packets.gen_puback(data['mid'], proto_ver=5, reason_code=0x00, properties=props)
data['label'] = "qos1 len >5"
mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-c2b-qos1-len.exe"), [], do_test, data)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-c2b-qos1-len.exe"), [], do_test, data)
