#!/usr/bin/env python3

# Test whether a client with a will delay recovers on the client reconnecting
# MQTT 5

from mosq_test_helper import *


def do_test(start_broker, clean_session):
    rc = 1

    mid = 1
    connect1_packet = mosq_test.gen_connect("will-delay-recovery", proto_ver=5)
    connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    connect_props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 30)
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_WILL_DELAY_INTERVAL, 3)
    connect2_packet = mosq_test.gen_connect("will-delay-recovery-helper", proto_ver=5, will_topic="will/delay/recovery/test", will_payload=b"will delay", will_properties=props, clean_session=clean_session, properties=connect_props)
    connack2a_packet = mosq_test.gen_connack(rc=0, proto_ver=5)
    if clean_session == True:
        connack2b_packet = mosq_test.gen_connack(rc=0, proto_ver=5)
    else:
        connack2b_packet = mosq_test.gen_connack(rc=0, proto_ver=5, flags=1)

    subscribe_packet = mosq_test.gen_subscribe(mid, "will/delay/recovery/test", 0, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    connect2_packet_clear = mosq_test.gen_connect("will-delay-recovery-helper", proto_ver=5)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=30, port=port)
        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2a_packet, timeout=30, port=port)
        sock2.close()

        time.sleep(1)
        sock2 = mosq_test.do_client_connect(connect2_packet, connack2b_packet, timeout=30, port=port)
        time.sleep(3)

        # The client2 has reconnected within the will delay interval, which has now
        # passed. We should not have received the will at this point.
        mosq_test.do_ping(sock1)
        rc = 0

        sock1.close()
        sock2.close()

        sock2 = mosq_test.do_client_connect(connect2_packet_clear, connack1_packet, timeout=30, port=port)
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
    rc = do_test(start_broker, clean_session=True)
    if rc:
        return rc
    rc = do_test(start_broker, clean_session=False)
    if rc:
        return rc
    return 0

if __name__ == '__main__':
    all_tests(True)
