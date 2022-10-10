#!/usr/bin/env python3

# Test whether a client that connects with a will delay that is shorter than
# their session expiry interval has their will published.
# MQTT 5
# https://github.com/eclipse/mosquitto/issues/1401

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1

    mid = 1
    connect1_packet = mosq_test.gen_connect("will-session-exp2", proto_ver=5)
    connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    will_props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_WILL_DELAY_INTERVAL, 2)
    connect_props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 4)

    connect2_packet = mosq_test.gen_connect("will-session-exp2-helper", proto_ver=5, properties=connect_props, will_topic="will/session/expiry2/test", will_payload=b"will delay", will_qos=2, will_properties=will_props)
    connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    subscribe_packet = mosq_test.gen_subscribe(mid, "will/session/expiry2/test", 0, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    publish_packet = mosq_test.gen_publish("will/session/expiry2/test", qos=0, payload="will delay", proto_ver=5)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=30, port=port, connack_error="connack1")
        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=30, port=port, connack_error="connack2")
        time.sleep(1)
        sock2.close()

        # Wait for session to expire
        time.sleep(3)
        mosq_test.expect_packet(sock1, "publish", publish_packet)
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
    return do_test(start_broker)

if __name__ == '__main__':
    all_tests(True)
