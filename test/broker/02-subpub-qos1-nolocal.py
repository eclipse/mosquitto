#!/usr/bin/env python3

# Test whether a client subscribed to a topic does not receive its own message
# sent to that topic if no local is set.
# MQTT v5

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1
    connect_packet = mosq_test.gen_connect("02-subpub-qos1-nolocal", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 530
    subscribe_packet = mosq_test.gen_subscribe(mid, "02/subpub/qos1/nolocal/qos1", 1 | mqtt5_opts.MQTT_SUB_OPT_NO_LOCAL, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 1, proto_ver=5)

    mid = 531
    subscribe2_packet = mosq_test.gen_subscribe(mid, "02/subpub/qos1/nolocal/receive", 1, proto_ver=5)
    suback2_packet = mosq_test.gen_suback(mid, 1, proto_ver=5)

    mid = 300
    publish_packet = mosq_test.gen_publish("02/subpub/qos1/nolocal/qos1", qos=1, mid=mid, payload="message", proto_ver=5)
    puback_packet = mosq_test.gen_puback(mid, proto_ver=5)

    mid = 301
    publish2_packet = mosq_test.gen_publish("02/subpub/qos1/nolocal/receive", qos=1, mid=mid, payload="success", proto_ver=5)
    puback2_packet = mosq_test.gen_puback(mid, proto_ver=5)

    mid = 1
    publish3_packet = mosq_test.gen_publish("02/subpub/qos1/nolocal/receive", qos=1, mid=mid, payload="success", proto_ver=5)


    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        mosq_test.do_send_receive(sock, subscribe2_packet, suback2_packet, "suback2")

        mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")
        sock.send(publish2_packet)

        mosq_test.receive_unordered(sock, puback2_packet, publish3_packet, "puback2/publish3")
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
