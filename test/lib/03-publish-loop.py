#!/usr/bin/env python3

from mosq_test_helper import *

def do_test(conn, data):
    connect_packet = mqtt_packets.gen_connect("loop-test", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "loop/test", 0, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=5)

    disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5)

    publish_packet = mqtt_packets.gen_publish("loop/test", qos=0, payload="message", proto_ver=5)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_receive_send(conn, subscribe_packet, suback_packet, "subscribe")
    conn.send(publish_packet)
    mosq_test.expect_packet(conn, "publish", publish_packet)
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)


mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-loop.exe"), [], do_test, None)
mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-loop-forever.exe"), [], do_test, None)
mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-loop-manual.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_THREADING"]):
    mosq_test.client_test(Path("c", mosq_test.get_build_type(), "03-publish-loop-start.exe"), [], do_test, None)
if mosq_test.check_features(["WITH_LIB_CPP"]):
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-loop.exe"), [], do_test, None)
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-loop-forever.exe"), [], do_test, None)
    mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-loop-manual.exe"), [], do_test, None)
    if mosq_test.check_features(["WITH_THREADING"]):
        mosq_test.client_test(Path("cpp", mosq_test.get_build_type(), "03-publish-loop-start.exe"), [], do_test, None)
