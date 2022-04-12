#!/usr/bin/env python3

# Test whether a PUBREC with reason code >= 0x80 is handled correctly

from mosq_test_helper import *

def helper(port):
    connect_packet = mosq_test.gen_connect("02-subpub-qos2-pubrec-error-helper")
    connack_packet = mosq_test.gen_connack(rc=0)

    mid = 1
    publish_1_packet = mosq_test.gen_publish("02/subpub/error/qos2/pubrec/rejected", qos=2, mid=mid, payload="rejected-message")
    pubrec_1_packet = mosq_test.gen_pubrec(mid)
    pubrel_1_packet = mosq_test.gen_pubrel(mid)
    pubcomp_1_packet = mosq_test.gen_pubcomp(mid)

    mid = 2
    publish_2_packet = mosq_test.gen_publish("02/subpub/error/qos2/pubrec/accepted", qos=2, mid=mid, payload="accepted-message")
    pubrec_2_packet = mosq_test.gen_pubrec(mid)
    pubrel_2_packet = mosq_test.gen_pubrel(mid)
    pubcomp_2_packet = mosq_test.gen_pubcomp(mid)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, connack_error="helper connack", port=port)

    mosq_test.do_send_receive(sock, publish_1_packet, pubrec_1_packet, "helper pubrec")
    mosq_test.do_send_receive(sock, pubrel_1_packet, pubcomp_1_packet, "helper pubcomp")

    mosq_test.do_send_receive(sock, publish_2_packet, pubrec_2_packet, "helper pubrec")
    mosq_test.do_send_receive(sock, pubrel_2_packet, pubcomp_2_packet, "helper pubcomp")
    sock.close()


def do_test(start_broker):
    rc = 1
    connect_packet = mosq_test.gen_connect("02-subpub-qos2-pubrec-error", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "02/subpub/error/qos2/pubrec/+", 2, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 2, proto_ver=5)

    mid = 1
    publish_1_packet = mosq_test.gen_publish("02/subpub/error/qos2/pubrec/rejected", qos=2, mid=mid, payload="rejected-message", proto_ver=5)
    pubrec_1_packet = mosq_test.gen_pubrec(mid, proto_ver=5, reason_code=0x80)

    mid = 2
    publish_2_packet = mosq_test.gen_publish("02/subpub/error/qos2/pubrec/accepted", qos=2, mid=mid, payload="accepted-message", proto_ver=5)
    pubrec_2_packet = mosq_test.gen_pubrec(mid, proto_ver=5)
    pubrel_2_packet = mosq_test.gen_pubrel(mid, proto_ver=5)
    pubcomp_2_packet = mosq_test.gen_pubcomp(mid, proto_ver=5)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        helper(port)

        # Should have now received a publish command
        mosq_test.expect_packet(sock, "publish 1", publish_1_packet)
        sock.send(pubrec_1_packet)

        mosq_test.expect_packet(sock, "publish 2", publish_2_packet)
        mosq_test.do_send_receive(sock, pubrec_2_packet, pubrel_2_packet, "pubrel 2")
        sock.send(pubcomp_2_packet)
        rc = 0

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
    return do_test(start_broker)

if __name__ == '__main__':
    all_tests(True)
