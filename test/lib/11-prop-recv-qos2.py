#!/usr/bin/env python3

# Check whether the v5 message callback gets the properties

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mqtt_packets.gen_connect("prop-test", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    mid = 1
    props = mqtt5_props.gen_string_prop(mqtt5_props.CONTENT_TYPE, "plain/text")
    props += mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "msg/123")
    publish_packet = mqtt_packets.gen_publish("prop/test", mid=mid, qos=2, payload="message", proto_ver=5, properties=props)
    pubrec_packet = mqtt_packets.gen_pubrec(mid=mid, proto_ver=5)
    pubrel_packet = mqtt_packets.gen_pubrel(mid=mid, proto_ver=5)
    pubcomp_packet = mqtt_packets.gen_pubcomp(mid=mid, proto_ver=5)

    ok_packet = mqtt_packets.gen_publish("ok", qos=0, payload="ok", proto_ver=5)

    disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_send_receive(conn, publish_packet, pubrec_packet, "pubrec")
    mosq_test.do_send_receive(conn, pubrel_packet, pubcomp_packet, "pubcomp")
    mosq_test.expect_packet(conn, "ok", ok_packet)

    conn.close()


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "11-prop-recv.exe"), ["2"], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "11-prop-recv.exe"), ["2"], do_test, None)
