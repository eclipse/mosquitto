#!/usr/bin/env python3

# Test whether a client will is transmitted correctly.

from mosq_test_helper import *


def do_test(start_broker, proto_ver, clean_session):
    rc = 1
    mid = 53
    connect1_packet = mosq_test.gen_connect("will-qos0-test", proto_ver=proto_ver)
    connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    connect2_packet = mosq_test.gen_connect("will-qos0-helper", will_topic="will/qos0/test", will_payload=b"will-message", clean_session=clean_session, proto_ver=proto_ver, session_expiry=60)
    connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    subscribe_packet = mosq_test.gen_subscribe(mid, "will/qos0/test", 0, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=proto_ver)

    publish_packet = mosq_test.gen_publish("will/qos0/test", qos=0, payload="will-message", proto_ver=proto_ver)

    connect2_packet_clear = mosq_test.gen_connect("will-qos0-helper", proto_ver=proto_ver)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=5, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, port=port, timeout=5)
        sock2.close()

        mosq_test.expect_packet(sock, "publish", publish_packet)
        rc = 0

        sock.close()

        sock = mosq_test.do_client_connect(connect2_packet_clear, connack1_packet, timeout=5, port=port)
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
                exit(rc)
        else:
            return rc


def all_tests(start_broker=False):
    rc = do_test(start_broker, proto_ver=4, clean_session=True)
    if rc:
        return rc;
    rc = do_test(start_broker, proto_ver=4, clean_session=False)
    if rc:
        return rc;
    rc = do_test(start_broker, proto_ver=5, clean_session=True)
    if rc:
        return rc;
    rc = do_test(start_broker, proto_ver=5, clean_session=False)
    if rc:
        return rc;
    return 0

if __name__ == '__main__':
    all_tests(True)
