#!/usr/bin/env python3

# Check whether the broker handles a v5 PUBREC, PUBCOMP with all combinations
# of with/without reason code and properties.

from mosq_test_helper import *

def helper(port):
    connect_packet = mosq_test.gen_connect("03-b2c-qos2-len-helper")
    connack_packet = mosq_test.gen_connack(rc=0)

    mid = 1
    publish_packet = mosq_test.gen_publish("03/b2c/qos2/len/test", qos=2, mid=mid, payload="len-message")
    pubrec_packet = mosq_test.gen_pubrec(mid)
    pubrel_packet = mosq_test.gen_pubrel(mid)
    pubcomp_packet = mosq_test.gen_pubcomp(mid)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, connack_error="helper connack", port=port)

    mosq_test.do_send_receive(sock, publish_packet, pubrec_packet, "helper pubrec")
    mosq_test.do_send_receive(sock, pubrel_packet, pubcomp_packet, "helper pubcomp")
    sock.close()


def do_test(start_broker, test, pubrec_packet, pubcomp_packet):
    rc = 1
    mid = 3265
    connect_packet = mosq_test.gen_connect("03-b2c-qos2-len-test", clean_session=False, proto_ver=5)
    connack_packet = mosq_test.gen_connack(flags=0, rc=0, proto_ver=5)

    subscribe_packet = mosq_test.gen_subscribe(mid, "03/b2c/qos2/len/test", 2, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 2, proto_ver=5)

    mid = 1
    publish_packet = mosq_test.gen_publish("03/b2c/qos2/len/test", qos=2, mid=mid, payload="len-message", proto_ver=5)
    pubrel_packet = mosq_test.gen_pubrel(mid)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        helper(port)
        # Should have now received a publish command

        mosq_test.expect_packet(sock, "publish", publish_packet)
        mosq_test.do_send_receive(sock, pubrec_packet, pubrel_packet, "pubrel")
        sock.send(pubcomp_packet)

        mosq_test.do_ping(sock)
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
                print(test)
                exit(rc)
        else:
            return rc


def all_tests(start_broker=False):
    # No reason code, no properties
    pubrec_packet = mosq_test.gen_pubrec(1)
    pubcomp_packet = mosq_test.gen_pubcomp(1)
    rc = do_test(start_broker, "qos2 len 2", pubrec_packet, pubcomp_packet)
    if rc:
        return rc

    # Reason code, no properties
    pubrec_packet = mosq_test.gen_pubrec(1, proto_ver=5, reason_code=0x00)
    pubcomp_packet = mosq_test.gen_pubcomp(1, proto_ver=5, reason_code=0x00)
    rc = do_test(start_broker, "qos2 len 3", pubrec_packet, pubcomp_packet)
    if rc:
        return rc

    # Reason code, empty properties
    pubrec_packet = mosq_test.gen_pubrec(1, proto_ver=5, reason_code=0x00, properties="")
    pubcomp_packet = mosq_test.gen_pubcomp(1, proto_ver=5, reason_code=0x00, properties="")
    rc = do_test(start_broker, "qos2 len 4", pubrec_packet, pubcomp_packet)
    if rc:
        return rc

    # Reason code, one property
    props = mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "key", "value")
    pubrec_packet = mosq_test.gen_pubrec(1, proto_ver=5, reason_code=0x00, properties=props)
    props = mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "key", "value")
    pubcomp_packet = mosq_test.gen_pubcomp(1, proto_ver=5, reason_code=0x00, properties=props)
    rc = do_test(start_broker, "qos2 len >5", pubrec_packet, pubcomp_packet)
    if rc:
        return rc
    return 0

if __name__ == '__main__':
    all_tests(True)
