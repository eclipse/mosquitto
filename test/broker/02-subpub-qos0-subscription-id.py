#!/usr/bin/env python3

# Does setting and updating subscription identifiers work as expected?
# MQTT v5

from mosq_test_helper import *

def do_test(start_broker, proto_ver):
    rc = 1
    connect_packet = mosq_test.gen_connect("02-subpub-subid", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 1
    props = mqtt5_props.gen_varint_prop(mqtt5_props.PROP_SUBSCRIPTION_IDENTIFIER, 1)
    subscribe1_packet = mosq_test.gen_subscribe(mid, "02/subpub/subid/id1", 0, proto_ver=5, properties=props)
    suback1_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    mid = 2
    props = mqtt5_props.gen_varint_prop(mqtt5_props.PROP_SUBSCRIPTION_IDENTIFIER, 14)
    subscribe2_packet = mosq_test.gen_subscribe(mid, "02/subpub/subid/+/id2", 0, proto_ver=5, properties=props)
    suback2_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    mid = 3
    subscribe3_packet = mosq_test.gen_subscribe(mid, "02/subpub/subid/noid", 0, proto_ver=5)
    suback3_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    # Updated version of subscribe1, now without a subscription identifier
    mid = 4
    subscribe1u_packet = mosq_test.gen_subscribe(mid, "02/subpub/subid/id1", 0, proto_ver=5)
    suback1u_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    # Updated version of subscribe2, with a new subscription identifier
    mid = 5
    props = mqtt5_props.gen_varint_prop(mqtt5_props.PROP_SUBSCRIPTION_IDENTIFIER, 19)
    subscribe2u_packet = mosq_test.gen_subscribe(mid, "02/subpub/subid/+/id2", 0, proto_ver=5, properties=props)
    suback2u_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    # Updated version of subscribe3, now with a subscription identifier
    mid = 6
    props = mqtt5_props.gen_varint_prop(mqtt5_props.PROP_SUBSCRIPTION_IDENTIFIER, 21)
    subscribe3u_packet = mosq_test.gen_subscribe(mid, "02/subpub/subid/noid", 0, proto_ver=5, properties=props)
    suback3u_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)


    publish1_packet = mosq_test.gen_publish("02/subpub/subid/id1", qos=0, payload="message1", proto_ver=5)

    props = mqtt5_props.gen_varint_prop(mqtt5_props.PROP_SUBSCRIPTION_IDENTIFIER, 1)
    publish1r_packet = mosq_test.gen_publish("02/subpub/subid/id1", qos=0, payload="message1", proto_ver=5, properties=props)

    publish2_packet = mosq_test.gen_publish("02/subpub/subid/test/id2", qos=0, payload="message2", proto_ver=5)
    props = mqtt5_props.gen_varint_prop(mqtt5_props.PROP_SUBSCRIPTION_IDENTIFIER, 14)
    publish2r_packet = mosq_test.gen_publish("02/subpub/subid/test/id2", qos=0, payload="message2", proto_ver=5, properties=props)

    publish3_packet = mosq_test.gen_publish("02/subpub/subid/noid", qos=0, payload="message3", proto_ver=5)


    # Updated version of publish1r, now with no id
    publish1ru_packet = mosq_test.gen_publish("02/subpub/subid/id1", qos=0, payload="message1", proto_ver=5)

    # Updated verison of publish2r, with updated id
    props = mqtt5_props.gen_varint_prop(mqtt5_props.PROP_SUBSCRIPTION_IDENTIFIER, 19)
    publish2ru_packet = mosq_test.gen_publish("02/subpub/subid/test/id2", qos=0, payload="message2", proto_ver=5, properties=props)

    # Updated version of publish3r, now with an id
    props = mqtt5_props.gen_varint_prop(mqtt5_props.PROP_SUBSCRIPTION_IDENTIFIER, 21)
    publish3ru_packet = mosq_test.gen_publish("02/subpub/subid/noid", qos=0, payload="message3", proto_ver=5, properties=props)


    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, subscribe1_packet, suback1_packet, "suback1")
        mosq_test.do_send_receive(sock, subscribe2_packet, suback2_packet, "suback2")
        mosq_test.do_send_receive(sock, subscribe3_packet, suback3_packet, "suback3")

        mosq_test.do_send_receive(sock, publish3_packet, publish3_packet, "publish3")
        mosq_test.do_send_receive(sock, publish2_packet, publish2r_packet, "publish2")
        mosq_test.do_send_receive(sock, publish1_packet, publish1r_packet, "publish1")

        # Now update the subscription identifiers
        mosq_test.do_send_receive(sock, subscribe1u_packet, suback1u_packet, "suback1u")
        mosq_test.do_send_receive(sock, subscribe2u_packet, suback2u_packet, "suback2u")
        mosq_test.do_send_receive(sock, subscribe3u_packet, suback3u_packet, "suback3u")

        mosq_test.do_send_receive(sock, publish2_packet, publish2ru_packet, "publish2u")
        mosq_test.do_send_receive(sock, publish3_packet, publish3ru_packet, "publish3u")
        mosq_test.do_send_receive(sock, publish1_packet, publish1ru_packet, "publish1u")

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
    return do_test(start_broker, proto_ver=5)

if __name__ == '__main__':
    all_tests(True)
