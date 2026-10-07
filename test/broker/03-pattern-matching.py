#!/usr/bin/env python3

from mosq_test_helper import *

def pattern_test(sub_topic, pub_topic):
    connect_packet = mqtt_packets.gen_connect("pattern-sub-test")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    publish_packet = mqtt_packets.gen_publish(pub_topic, qos=0, payload="message")
    publish_retained_packet = mqtt_packets.gen_publish(pub_topic, qos=0, retain=True, payload="message")

    mid = 312
    subscribe_packet = mqtt_packets.gen_subscribe(mid, sub_topic, 0)
    suback_packet = mqtt_packets.gen_suback(mid, 0)

    mid = 234;
    unsubscribe_packet = mqtt_packets.gen_unsubscribe(mid, sub_topic)
    unsuback_packet = mqtt_packets.gen_unsuback(mid)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    sock.send(publish_retained_packet)

    mosq_test.expect_packet(sock, "publish", publish_packet)
    mosq_test.do_send_receive(sock, unsubscribe_packet, unsuback_packet, "unsuback")
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
    mosq_test.expect_packet(sock, "publish retained", publish_retained_packet)
    sock.send(mqtt_packets.gen_publish(pub_topic, qos=0, retain=True, payload="")) # Clear retain
    sock.close()


port = mosq_test.get_port()
broker = MosquittoBroker(port=port)

with broker:
    pattern_test("#", "test/topic")
    pattern_test("#", "/test/topic")
    pattern_test("foo/#", "foo/bar/baz")
    pattern_test("foo/+/baz", "foo/bar/baz")
    pattern_test("foo/+/baz/#", "foo/bar/baz")
    pattern_test("foo/+/baz/#", "foo/bar/baz/bar")
    pattern_test("foo/foo/baz/#", "foo/foo/baz/bar")
    pattern_test("foo/#", "foo")
    pattern_test("foo/#", "foo/")
    pattern_test("/#", "/foo")
    pattern_test("test/topic/", "test/topic/")
    pattern_test("test/topic/+", "test/topic/")
    pattern_test("+/+/+/+/+/+/+/+/+/+/test", "one/two/three/four/five/six/seven/eight/nine/ten/test")

    pattern_test("#", "test////a//topic")
    pattern_test("#", "/test////a//topic")
    pattern_test("foo/#", "foo//bar///baz")
    pattern_test("foo/+/baz", "foo//baz")
    pattern_test("foo/+/baz//", "foo//baz//")
    pattern_test("foo/+/baz/#", "foo//baz")
    pattern_test("foo/+/baz/#", "foo//baz/bar")
    pattern_test("foo//baz/#", "foo//baz/bar")
    pattern_test("foo/foo/baz/#", "foo/foo/baz/bar")
    pattern_test("/#", "////foo///bar")
