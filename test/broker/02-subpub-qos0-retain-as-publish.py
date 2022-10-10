#!/usr/bin/env python3

# Test whether a client subscribed to a topic with retain-as-published set works as expected.
# MQTT v5

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1
    connect_packet = mosq_test.gen_connect("02-subpub-qos0-rap", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 530
    subscribe1_packet = mosq_test.gen_subscribe(mid, "02/subpub/rap/normal", 0, proto_ver=5)
    suback1_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    mid = 531
    subscribe2_packet = mosq_test.gen_subscribe(mid, "02/subpub/rap/rap", 0 | mqtt5_opts.MQTT_SUB_OPT_RETAIN_AS_PUBLISHED, proto_ver=5)
    suback2_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    publish1_packet = mosq_test.gen_publish("02/subpub/rap/normal", qos=0, retain=True, payload="message", proto_ver=5)
    publish2_packet = mosq_test.gen_publish("02/subpub/rap/rap", qos=0, retain=True, payload="message", proto_ver=5)

    publish1r_packet = mosq_test.gen_publish("02/subpub/rap/normal", qos=0, retain=False, payload="message", proto_ver=5)
    publish2r_packet = mosq_test.gen_publish("02/subpub/rap/rap", qos=0, retain=True, payload="message", proto_ver=5)

    mid = 1
    publish3_packet = mosq_test.gen_publish("02/subpub/rap/receive", qos=1, mid=mid, payload="success", proto_ver=5)


    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, subscribe1_packet, suback1_packet, "suback1")
        mosq_test.do_send_receive(sock, subscribe2_packet, suback2_packet, "suback2")

        mosq_test.do_send_receive(sock, publish1_packet, publish1r_packet, "publish1")
        mosq_test.do_send_receive(sock, publish2_packet, publish2r_packet, "publish2")
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
                exit(rc)
        else:
            return rc


def all_tests(start_broker=False):
    return do_test(start_broker)

if __name__ == '__main__':
    all_tests(True)
