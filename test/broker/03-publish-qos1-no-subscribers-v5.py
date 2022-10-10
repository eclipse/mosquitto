#!/usr/bin/env python3

# Test whether a PUBLISH to a topic with QoS 1 results in the correct PUBACK
# packet when there are no subscribers.

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1
    connect_packet = mosq_test.gen_connect("03-pub-qos1-no-subs", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 1
    publish1_packet = mosq_test.gen_publish("03B/no/subs/pub", qos=1, mid=mid, payload="message", proto_ver=5)
    puback1_packet = mosq_test.gen_puback(mid, proto_ver=5, reason_code=mqtt5_rc.MQTT_RC_NO_MATCHING_SUBSCRIBERS)

    mid = 2
    publish2_packet = mosq_test.gen_publish("03B/no/subs/pub/qos1", qos=1, mid=mid, payload="message", proto_ver=5)
    puback2_packet = mosq_test.gen_puback(mid, proto_ver=5, reason_code=mqtt5_rc.MQTT_RC_NO_MATCHING_SUBSCRIBERS)

    mid = 3
    publish3_packet = mosq_test.gen_publish("03B/no/subs/pub/qos1/test", qos=1, mid=mid, payload="message", proto_ver=5)
    puback3_packet = mosq_test.gen_puback(mid, proto_ver=5, reason_code=mqtt5_rc.MQTT_RC_NO_MATCHING_SUBSCRIBERS)

    mid = 4
    publish4_packet = mosq_test.gen_publish("03B/no/subs/pub/qos1/test", qos=1, mid=mid, payload="message", proto_ver=5, retain=True)
    puback4_packet = mosq_test.gen_puback(mid, proto_ver=5, reason_code=mqtt5_rc.MQTT_RC_NO_MATCHING_SUBSCRIBERS)

    mid = 5
    publish1b_packet = mosq_test.gen_publish("03B/no/subs/pub", qos=1, mid=mid, payload="message", proto_ver=5)
    puback1b_packet = mosq_test.gen_puback(mid, proto_ver=5, reason_code=mqtt5_rc.MQTT_RC_NO_MATCHING_SUBSCRIBERS)

    mid = 6
    publish2b_packet = mosq_test.gen_publish("03B/no/subs/pub/qos1", qos=1, mid=mid, payload="message", proto_ver=5)
    puback2b_packet = mosq_test.gen_puback(mid, proto_ver=5, reason_code=mqtt5_rc.MQTT_RC_NO_MATCHING_SUBSCRIBERS)

    mid = 7
    publish3b_packet = mosq_test.gen_publish("03B/no/subs/pub/qos1/test", qos=1, mid=mid, payload="message", proto_ver=5)
    puback3b_packet = mosq_test.gen_puback(mid, proto_ver=5, reason_code=mqtt5_rc.MQTT_RC_NO_MATCHING_SUBSCRIBERS)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)

        # None of the pub/qos1/test topic tree exists here
        mosq_test.do_send_receive(sock, publish1_packet, puback1_packet, "puback1a")
        mosq_test.do_send_receive(sock, publish2_packet, puback2_packet, "puback2a")
        mosq_test.do_send_receive(sock, publish3_packet, puback3_packet, "puback3a")

        # This publish sets a retained message, which means the topic tree exists
        mosq_test.do_send_receive(sock, publish4_packet, puback4_packet, "puback4")

        # So now test again
        mosq_test.do_send_receive(sock, publish1b_packet, puback1b_packet, "puback1b")
        mosq_test.do_send_receive(sock, publish2b_packet, puback2b_packet, "puback2b")
        mosq_test.do_send_receive(sock, publish3b_packet, puback3b_packet, "puback3b")

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


def all_tests(start_broker=False):
    return do_test(start_broker)

if __name__ == '__main__':
    all_tests(True)
