#!/usr/bin/env python3

# Test what happens if a client reuses an in-use mid with a different message.

from mosq_test_helper import *

def do_test(proto_ver):
    rc = 1
    connect_packet = mosq_test.gen_connect("pub-qos2-test", proto_ver=proto_ver)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 312
    publish_packet1 = mosq_test.gen_publish("pub/qos2/test", qos=2, mid=mid, payload="message", proto_ver=proto_ver)
    pubrec_packet = mosq_test.gen_pubrec(mid, proto_ver=proto_ver)
    pubrel_packet = mosq_test.gen_pubrel(mid, proto_ver=proto_ver)
    pubcomp_packet = mosq_test.gen_pubcomp(mid, proto_ver=proto_ver)

    mid = 312
    publish_packet2 = mosq_test.gen_publish("pub/qos2/reuse", qos=2, mid=mid, payload="message", proto_ver=proto_ver)

    sub_connect_packet = mosq_test.gen_connect("sub-qos2-test", proto_ver=proto_ver)
    sub_connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "#", 2, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 2, proto_ver=proto_ver)
    mid = 1
    publish_packet_expected = mosq_test.gen_publish("pub/qos2/reuse", qos=2, mid=mid, payload="message", proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        ssock = mosq_test.do_client_connect(sub_connect_packet, sub_connack_packet, port=port)
        mosq_test.do_send_receive(ssock, subscribe_packet, suback_packet, "suback")

        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, publish_packet1, pubrec_packet, "pubrec1")
        mosq_test.do_send_receive(sock, publish_packet2, pubrec_packet, "pubrec2")
        mosq_test.do_send_receive(sock, pubrel_packet, pubcomp_packet, "pubcomp")

        mosq_test.expect_packet(ssock, "publish", publish_packet_expected)

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
            print("proto_ver=%d" % (proto_ver))
            exit(rc)


do_test(proto_ver=4)
do_test(proto_ver=5)
exit(0)
