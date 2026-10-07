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

def do_test(proto_ver):
    connect_packet_sub_persistent = mqtt_packets.gen_connect("flipflop-test", clean_session=False, proto_ver=proto_ver)
    connect_packet_sub_clean = mqtt_packets.gen_connect("flipflop-test", clean_session=True, proto_ver=proto_ver)
    connack_packet_sub = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    connect_packet_pub = mqtt_packets.gen_connect("flipflop-test-pub", proto_ver=proto_ver)
    connack_packet_pub = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    mid=1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "flipflop/test", 1, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 1, proto_ver=proto_ver)

    mid=1
    publish_packet = mqtt_packets.gen_publish("flipflop/test", qos=1, mid=mid, payload="message", proto_ver=proto_ver)
    puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)


    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)

    with broker:
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
        sub_sock.close()

        sub_sock = mosq_test.do_client_connect(connect_packet_sub_clean, connack_packet_sub, port=port)
        sub_sock.close()


if __name__ == '__main__':
    do_test(proto_ver=4)
    do_test(proto_ver=5)
