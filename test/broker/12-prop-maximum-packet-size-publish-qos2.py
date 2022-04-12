#!/usr/bin/env python3

# Test whether maximum packet size is honoured on a PUBLISH to a client
# MQTTv5

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1

    props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_MAXIMUM_PACKET_SIZE, 40)
    connect_packet = mosq_test.gen_connect("12-max-publish-qos2", proto_ver=5, properties=props)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "12/max/publish/qos2/test/topic", 2, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 2, proto_ver=5)

    mid=1
    publish1_packet = mosq_test.gen_publish(topic="12/max/publish/qos2/test/topic", mid=mid, qos=2, payload="12345678901234567890", proto_ver=5)
    pubrec1_packet = mosq_test.gen_pubrec(mid, proto_ver=5)
    pubrel1_packet = mosq_test.gen_pubrel(mid, proto_ver=5)
    pubcomp1_packet = mosq_test.gen_pubcomp(mid, proto_ver=5)

    mid=2
    publish2_packet = mosq_test.gen_publish(topic="12/max/publish/qos2/test/topic", mid=mid, qos=2, payload="7890", proto_ver=5)
    pubrec2_packet = mosq_test.gen_pubrec(mid, proto_ver=5)
    pubrel2_packet = mosq_test.gen_pubrel(mid, proto_ver=5)
    pubcomp2_packet = mosq_test.gen_pubcomp(mid, proto_ver=5)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet)

        mosq_test.do_send_receive(sock, publish1_packet, pubrec1_packet, "pubrec 1")
        mosq_test.do_send_receive(sock, pubrel1_packet, pubcomp1_packet, "pubcomp 1")

        # We shouldn't receive the publish here because it is > MAXIMUM_PACKET_SIZE
        mosq_test.do_ping(sock)

        mosq_test.do_send_receive(sock, publish2_packet, pubrec2_packet, "pubrec 2")
        sock.send(pubrel2_packet)
        mosq_test.receive_unordered(sock, pubcomp2_packet, publish2_packet, "pubcomp 2/publish2")
        rc = 0
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
