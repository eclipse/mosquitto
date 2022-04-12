#!/usr/bin/env python3

# Test whether a client will is transmitted with a delay correctly.
# MQTT 5

from mosq_test_helper import *

def do_test(start_broker, clean_session):
    rc = 1

    mid = 1
    connect1_packet = mosq_test.gen_connect("will-delay-test", proto_ver=5)
    connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_WILL_DELAY_INTERVAL, 3)
    connect2_packet = mosq_test.gen_connect("will-delay-helper", proto_ver=5, will_topic="will/delay/test", will_payload=b"will delay", will_qos=2, will_properties=props, clean_session=clean_session)
    connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    subscribe_packet = mosq_test.gen_subscribe(mid, "will/delay/test", 0, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    publish_packet = mosq_test.gen_publish("will/delay/test", qos=0, payload="will delay", proto_ver=5)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=30, port=port)
        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=30, port=port)
        sock2.close()

        t_start = time.time()
        mosq_test.expect_packet(sock1, "publish", publish_packet)
        t_finish = time.time()
        if t_finish - t_start > 2 and t_finish - t_start < 5:
            rc = 0

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
    rc = do_test(start_broker, clean_session=True)
    if rc:
        return rc
    rc = do_test(start_broker, clean_session=False)
    if rc:
        return rc
    return 0

if __name__ == '__main__':
    all_tests(True)
