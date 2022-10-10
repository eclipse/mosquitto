#!/usr/bin/env python3

# Check whether the broker handles a v5 PUBACK with all combinations
# of with/without reason code and properties.

from mosq_test_helper import *

def helper(port):
    connect_packet = mosq_test.gen_connect("03-b2c-qos1-len-helper")
    connack_packet = mosq_test.gen_connack(rc=0)
    mid = 1
    publish_packet = mosq_test.gen_publish("03/b2c/qos1/len/test", qos=1, mid=mid, payload="len-message")
    puback_packet = mosq_test.gen_puback(mid)
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, connack_error="helper connack", port=port)
    mosq_test.do_send_receive(sock, publish_packet, puback_packet, "helper puback")
    sock.close()


def do_test(start_broker, test, puback_packet):
    rc = 1
    mid = 3265
    connect_packet = mosq_test.gen_connect("03-b2c-qos1-len", clean_session=False, proto_ver=5)
    connack_packet = mosq_test.gen_connack(flags=0, rc=0, proto_ver=5)

    subscribe_packet = mosq_test.gen_subscribe(mid, "03/b2c/qos1/len/test", 1, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 1, proto_ver=5)

    mid = 1
    publish_packet = mosq_test.gen_publish("03/b2c/qos1/len/test", qos=1, mid=mid, payload="len-message", proto_ver=5)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        helper(port)
        # Should have now received a publish command

        mosq_test.expect_packet(sock, "publish", publish_packet)
        sock.send(puback_packet)

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
    puback_packet = mosq_test.gen_puback(1)
    rc = do_test(start_broker, "qos1 len 2", puback_packet)
    if rc:
        return rc

    # Reason code, no properties
    puback_packet = mosq_test.gen_puback(1, proto_ver=5, reason_code=0x00)
    rc = do_test(start_broker, "qos1 len 3", puback_packet)
    if rc:
        return rc

    # Reason code, empty properties
    puback_packet = mosq_test.gen_puback(1, proto_ver=5, reason_code=0x00, properties="")
    rc = do_test(start_broker, "qos1 len 4", puback_packet)
    if rc:
        return rc

    # Reason code, one property
    props = mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "key", "value")
    puback_packet = mosq_test.gen_puback(1, proto_ver=5, reason_code=0x00, properties=props)
    rc = do_test(start_broker, "qos1 len >5", puback_packet)
    if rc:
        return rc

    return 0

if __name__ == '__main__':
    all_tests(True)


