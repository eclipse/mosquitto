#!/usr/bin/env python3

# Test switching between persistence and a clean session.
#
# Bug #874:
#
#
# mosquitto_sub -i sub -t 'topic' -v -p 29883 -q 1 -d -c
# ^C
# mosquitto_sub -i sub -t 'topic' -v -p 29883 -q 1 -d
# ^C
#
# SUBSCRIBE to topic is no longer respected by mosquitto
#
# run:
#
# mosquitto_sub -i sub -t 'topic' -v -p 29883 -q 1 -d -c
#
# and in a separate shell
#
# mosquitto_pub -i pub -t topic -m 'hello' -p 29883 -q 1
#
# sub does not receive the message

from mosq_test_helper import *

def do_test(start_broker, proto_ver):
    rc = 1
    connect_packet_sub_persistent = mosq_test.gen_connect("flipflop-test", clean_session=False, proto_ver=proto_ver)
    connect_packet_sub_clean = mosq_test.gen_connect("flipflop-test", clean_session=True, proto_ver=proto_ver)
    connack_packet_sub = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    connect_packet_pub = mosq_test.gen_connect("flipflop-test-pub", proto_ver=proto_ver)
    connack_packet_pub = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    mid=1
    subscribe_packet = mosq_test.gen_subscribe(mid, "flipflop/test", 1, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 1, proto_ver=proto_ver)

    mid=1
    publish_packet = mosq_test.gen_publish("flipflop/test", qos=1, mid=mid, payload="message", proto_ver=proto_ver)
    puback_packet = mosq_test.gen_puback(mid, proto_ver=proto_ver)


    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        # mosquitto_sub -i sub -t 'topic' -q 1 -d -c
        sub_sock = mosq_test.do_client_connect(connect_packet_sub_persistent, connack_packet_sub, port=port)
        mosq_test.do_send_receive(sub_sock, subscribe_packet, suback_packet, "subscribe persistent 1")
        # And disconnect
        sub_sock.close()

        # mosquitto_sub -i sub -t 'topic' -q 1 -d
        sub_sock = mosq_test.do_client_connect(connect_packet_sub_clean, connack_packet_sub, port=port)
        mosq_test.do_send_receive(sub_sock, subscribe_packet, suback_packet, "subscribe clean")
        # And disconnect
        sub_sock.close()

        # mosquitto_sub -i sub -t 'topic' -v -q 1 -d -c
        sub_sock = mosq_test.do_client_connect(connect_packet_sub_persistent, connack_packet_sub, port=port)
        mosq_test.do_send_receive(sub_sock, subscribe_packet, suback_packet, "subscribe persistent 2")

        # and in a separate shell
        #
        # mosquitto_pub -i pub -t topic -m 'hello' -p 29883 -q 1
        pub_sock = mosq_test.do_client_connect(connect_packet_pub, connack_packet_pub, port=port)
        mosq_test.do_send_receive(pub_sock, publish_packet, puback_packet, "publish")

        mosq_test.expect_packet(sub_sock, "publish receive", publish_packet)
        rc = 0

        sub_sock.close()

        sub_sock = mosq_test.do_client_connect(connect_packet_sub_clean, connack_packet_sub, port=port)
        sub_sock.close()
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
                print("proto_ver=%d" % (proto_ver))
                exit(rc)
        else:
            return rc


def all_tests(start_broker=False):
    rc = do_test(start_broker, proto_ver=4)
    if rc:
        return rc;
    rc = do_test(start_broker, proto_ver=5)
    if rc:
        return rc;
    return 0

if __name__ == '__main__':
    all_tests(True)
