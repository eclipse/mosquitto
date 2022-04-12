#!/usr/bin/env python3

# Test whether a client with a will delay handles correctly on the client reconnecting
# First connection is durable, second is clean session, and without a will, so the will should not be received.
# MQTT 5

from mosq_test_helper import *


def do_test(start_broker):
    rc = 1

    mid = 1
    connect1_packet = mosq_test.gen_connect("will-delay-reconnect-test", proto_ver=5)
    connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_WILL_DELAY_INTERVAL, 3)
    connect2a_packet = mosq_test.gen_connect("will-delay-reconnect-helper", proto_ver=5, will_topic="will/delay/reconnect/test", will_payload=b"will delay", will_properties=props, clean_session=False)
    connack2a_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    connect2b_packet = mosq_test.gen_connect("will-delay-reconnect-helper", proto_ver=5, clean_session=True)
    connack2b_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    subscribe_packet = mosq_test.gen_subscribe(mid, "will/delay/reconnect/test", 0, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=30, port=port)
        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2a_packet, connack2a_packet, timeout=30, port=port)
        sock2.close()

        time.sleep(1)
        sock2 = mosq_test.do_client_connect(connect2b_packet, connack2b_packet, timeout=30, port=port)
        time.sleep(3)

        # The client2 has reconnected within the original will delay interval, which has now
        # passed, but it should have been deleted anyway. Disconnect and see
        # whether we get the old will. We should not.
        sock2.close()

        mosq_test.do_ping(sock1)
        rc = 0

        sock1.close()
        sock2.close()
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
