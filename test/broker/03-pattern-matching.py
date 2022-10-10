#!/usr/bin/env python3

from mosq_test_helper import *

def helper(port, pub_topic):
    connect_packet = mosq_test.gen_connect("test-helper")
    connack_packet = mosq_test.gen_connack(rc=0)

    publish_packet = mosq_test.gen_publish(pub_topic, qos=0, retain=True, payload="message")

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, connack_error="helper connack", port=port)
    sock.send(publish_packet)
    sock.close()


def pattern_test(sub_topic, pub_topic):
    rc = 1
    connect_packet = mosq_test.gen_connect("pattern-sub-test")
    connack_packet = mosq_test.gen_connack(rc=0)

    publish_packet = mosq_test.gen_publish(pub_topic, qos=0, payload="message")
    publish_retained_packet = mosq_test.gen_publish(pub_topic, qos=0, retain=True, payload="message")

    mid = 312
    subscribe_packet = mosq_test.gen_subscribe(mid, sub_topic, 0)
    suback_packet = mosq_test.gen_suback(mid, 0)

    mid = 234;
    unsubscribe_packet = mosq_test.gen_unsubscribe(mid, sub_topic)
    unsuback_packet = mosq_test.gen_unsuback(mid)

    port = mosq_test.get_port()
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        helper(port, pub_topic)

        mosq_test.expect_packet(sock, "publish", publish_packet)
        mosq_test.do_send_receive(sock, unsubscribe_packet, unsuback_packet, "unsuback")
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        mosq_test.expect_packet(sock, "publish retained", publish_retained_packet)
        rc = 0

        sock.close()
    except mosq_test.TestError:
        pass
    finally:
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            print(stdo.decode('utf-8'))
            sys.exit(rc)

    return rc

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

exit(0)

