#!/usr/bin/env python3

# Test whether a client will is transmitted when a client disconnects with DISCONNECT with will.
# MQTT 5

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1

    mid = 1
    connect1_packet = mosq_test.gen_connect("will-with-disconnect-test", proto_ver=5)
    connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    connect2_packet = mosq_test.gen_connect("will-with-disconnect-helper", proto_ver=5, will_topic="will/with/disconnect/test", will_payload=b"will delay", will_qos=2)
    connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=5)
    disconnect_packet = mosq_test.gen_disconnect(reason_code=4, proto_ver=5)

    subscribe_packet = mosq_test.gen_subscribe(mid, "will/with/disconnect/test", 0, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    publish_packet = mosq_test.gen_publish("will/with/disconnect/test", qos=0, payload="will delay", proto_ver=5)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=30, port=port)
        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=30, port=port)
        sock2.send(disconnect_packet)

        mosq_test.expect_packet(sock1, "publish", publish_packet)
        rc = 0

        sock2.close()
        sock1.close()
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
