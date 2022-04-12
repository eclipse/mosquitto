#!/usr/bin/env python3

# Test whether a clean session client has a QoS 1 message queued for it.

from mosq_test_helper import *

def helper(port):
    connect_packet = mosq_test.gen_connect("05-clean-qos1-test-helper")
    connack_packet = mosq_test.gen_connack(rc=0)

    mid = 128
    publish_packet = mosq_test.gen_publish("qos1/05-clean_session/test", qos=1, mid=mid, payload="clean-session-message")
    puback_packet = mosq_test.gen_puback(mid)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")

    sock.close()


def do_test(start_broker, proto_ver):
    rc = 1
    mid = 109
    connect_packet = mosq_test.gen_connect("05-clean-session", clean_session=False, proto_ver=proto_ver, session_expiry=60)
    connack1_packet = mosq_test.gen_connack(flags=0, rc=0, proto_ver=proto_ver)
    connack2_packet = mosq_test.gen_connack(flags=1, rc=0, proto_ver=proto_ver)

    disconnect_packet = mosq_test.gen_disconnect(proto_ver=proto_ver)

    subscribe_packet = mosq_test.gen_subscribe(mid, "qos1/05-clean_session/test", 1, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 1, proto_ver=proto_ver)

    mid = 1
    publish_packet = mosq_test.gen_publish("qos1/05-clean_session/test", qos=1, mid=mid, payload="clean-session-message", proto_ver=proto_ver)
    puback_packet = mosq_test.gen_puback(mid, proto_ver=proto_ver)

    connect_packet_clear = mosq_test.gen_connect("05-clean-session", clean_session=True, proto_ver=proto_ver, session_expiry=0)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack1_packet, port=port, connack_error="connack 1")
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        sock.send(disconnect_packet)
        sock.close()

        helper(port)

        # Now reconnect and expect a publish message.
        sock = mosq_test.do_client_connect(connect_packet, connack2_packet, timeout=30, port=port, connack_error="connack 2")
        mosq_test.expect_packet(sock, "publish", publish_packet)
        sock.send(puback_packet)
        rc = 0

        sock.close()

        # Clear the session
        sock = mosq_test.do_client_connect(connect_packet_clear, connack1_packet, port=port, connack_error="connack clear")
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
