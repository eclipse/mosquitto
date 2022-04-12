#!/usr/bin/env python3

# Test whether a PUBLISH to a topic starting with $ succeeds

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1
    mid = 19
    connect_packet = mosq_test.gen_connect("pub-dollar-test")
    connack_packet = mosq_test.gen_connack(rc=0)

    publish_packet = mosq_test.gen_publish("$test/test", qos=1, mid=mid, payload="message")
    puback_packet = mosq_test.gen_puback(mid)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")

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
