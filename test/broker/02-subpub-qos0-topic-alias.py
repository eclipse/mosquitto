#!/usr/bin/env python3

# Test whether "topic alias" works to the broker
# MQTT v5

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1
    connect1_packet = mosq_test.gen_connect("02-subpub-qos0-topic-alias", proto_ver=5)
    connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    connect2_packet = mosq_test.gen_connect("02-subpub-qos0-topic-alias-helper", proto_ver=5)
    connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "02/subpub/topic-alias/alias", 0, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    props = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_TOPIC_ALIAS, 3)
    publish1_packet = mosq_test.gen_publish("02/subpub/topic-alias/alias", qos=0, payload="message", proto_ver=5, properties=props)

    props = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_TOPIC_ALIAS, 3)
    publish2s_packet = mosq_test.gen_publish("", qos=0, payload="message", proto_ver=5, properties=props)
    publish2r_packet = mosq_test.gen_publish("02/subpub/topic-alias/alias", qos=0, payload="message", proto_ver=5)


    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=5, port=port)
        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=5, port=port)

        sock1.send(publish1_packet)

        mosq_test.do_send_receive(sock2, subscribe_packet, suback_packet, "suback")

        sock1.send(publish2s_packet)

        mosq_test.expect_packet(sock2, "publish2r", publish2r_packet)
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
