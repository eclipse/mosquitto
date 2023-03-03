#!/usr/bin/env python3

# Does an interrupted QoS 1 flow from broker to client get handled correctly?

from mosq_test_helper import *


def helper(port):
    connect_packet = mosq_test.gen_connect("03-bc2-disco-qos2-helper")
    connack_packet = mosq_test.gen_connack(rc=0)

    mid = 312
    publish_packet = mosq_test.gen_publish("03/b2c/qos2/disconnect/test", qos=2, mid=mid, payload="disconnect-message")
    pubrec_packet = mosq_test.gen_pubrec(mid)
    pubrel_packet = mosq_test.gen_pubrel(mid)
    pubcomp_packet = mosq_test.gen_pubcomp(mid)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, connack_error="helper connack", port=port)

    mosq_test.do_send_receive(sock, publish_packet, pubrec_packet, "helper pubrec")
    mosq_test.do_send_receive(sock, pubrel_packet, pubcomp_packet, "helper pubcomp")

    sock.close()


def do_test(start_broker, proto_ver):
    rc = 1
    mid = 3265
    connect_packet = mosq_test.gen_connect("03-b2c-disco-qos2-test", clean_session=False, proto_ver=proto_ver, session_expiry=60)
    connack1_packet = mosq_test.gen_connack(flags=0, rc=0, proto_ver=proto_ver)
    connack2_packet = mosq_test.gen_connack(flags=1, rc=0, proto_ver=proto_ver)
    connect_packet_clear = mosq_test.gen_connect("03-b2c-disco-qos2-test", proto_ver=proto_ver)

    subscribe_packet = mosq_test.gen_subscribe(mid, "03/b2c/qos2/disconnect/test", 2, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 2, proto_ver=proto_ver)

    mid = 1
    publish_packet = mosq_test.gen_publish("03/b2c/qos2/disconnect/test", qos=2, mid=mid, payload="disconnect-message", proto_ver=proto_ver)
    publish_dup_packet = mosq_test.gen_publish("03/b2c/qos2/disconnect/test", qos=2, mid=mid, payload="disconnect-message", dup=True, proto_ver=proto_ver)
    pubrec_packet = mosq_test.gen_pubrec(mid, proto_ver=proto_ver)
    pubrel_packet = mosq_test.gen_pubrel(mid, proto_ver=proto_ver)
    pubcomp_packet = mosq_test.gen_pubcomp(mid, proto_ver=proto_ver)

    mid = 3266
    publish2_packet = mosq_test.gen_publish("03/b2c/qos2/outgoing", qos=1, mid=mid, payload="outgoing-message", proto_ver=proto_ver)
    puback2_packet = mosq_test.gen_puback(mid, proto_ver=proto_ver)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack1_packet, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        helper(port)
        # Should have now received a publish command

        mosq_test.expect_packet(sock, "publish", publish_packet)
        # Send our outgoing message. When we disconnect the broker
        # should get rid of it and assume we're going to retry.
        sock.send(publish2_packet)
        sock.close()

        sock = mosq_test.do_client_connect(connect_packet, connack2_packet, port=port)
        mosq_test.expect_packet(sock, "dup publish", publish_dup_packet)
        mosq_test.do_send_receive(sock, pubrec_packet, pubrel_packet, "pubrel")

        sock.close()

        sock = mosq_test.do_client_connect(connect_packet, connack2_packet, port=port)
        mosq_test.expect_packet(sock, "dup pubrel", pubrel_packet)
        sock.send(pubcomp_packet)
        rc = 0
        sock.close()

        # Clear session
        sock = mosq_test.do_client_connect(connect_packet_clear, connack1_packet, port=port)
        sock.close()
    except mosq_test.TestError:
        pass
    finally:
        if start_broker:
            broker.terminate()
            if mosq_test.wait_for_subprocess(broker):
                print("broker not terminated")
                if rc == 0: rc=1
            (stdo, stde) = broker.communicate()
            if rc:
                print(stde.decode('utf-8'))
                print("proto_ver=%d" % (proto_ver))
                exit(rc)
        else:
            return rc


def all_tests(start_broker=False):
    rc = do_test(start_broker, proto_ver=4)
    if rc:
        return rc;
    rc = do_test(start_broker, proto_ver=5)
    if rc:
        return rc;
    return 0

if __name__ == '__main__':
    all_tests(True)
