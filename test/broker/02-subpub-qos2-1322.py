#!/usr/bin/env python3

# Test for issue 1322:

## restart mosquitto
#sudo systemctl restart mosquitto.service
#
## listen on topic1
#mosquitto_sub -t "topic1"
#
## publish to topic1 without clean session
#mosquitto_pub -t "topic1" -q 2 -c --id "foobar" -m "message1"
## message1 on topic1 is received as expected
#
## publish to topic2 without clean session
## IMPORTANT: no subscription to this topic is present on broker!
#mosquitto_pub -t "topic2" -q 2 -c --id "foobar" -m "message2"
## this goes nowhere, as no subscriber present
#
## publish to topic1 without clean session
#mosquitto_pub -t "topic1" -q 2 -c --id "foobar" -m "message3"
## message3 on topic1 IS NOT RECEIVED
#
## listen on topic2
#mosquitto_sub -t "topic2"
#
## publish to topic1 without clean session
#mosquitto_pub -t "topic1" -q 2 -c --id "foobar" -m "message4"
## message2 on topic2 is received incorrectly
#
## publish to topic1 without clean session
#mosquitto_pub -t "topic1" -q 2 -c --id "foobar" -m "message5"
## message5 on topic1 is received as expected (message4 was dropped)



from mosq_test_helper import *

def do_test(proto_ver):
    rc = 1
    pub_connect_packet = mqtt_packets.gen_connect("02-subpub-qos2-1322-pub", clean_session=False, proto_ver=proto_ver, session_expiry=60)
    pub_connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
    pub_connack2_packet = mqtt_packets.gen_connack(rc=0, flags=1, proto_ver=proto_ver)
    pub_connect_packet_clear = mqtt_packets.gen_connect("02-subpub-qos2-1322-pub", proto_ver=proto_ver)

    sub1_connect_packet = mqtt_packets.gen_connect("02-subpub-qos2-1322-sub1", proto_ver=proto_ver)
    sub1_connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    sub2_connect_packet = mqtt_packets.gen_connect("02-subpub-qos2-1322-sub2", proto_ver=proto_ver)
    sub2_connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 1
    subscribe1_packet = mqtt_packets.gen_subscribe(mid, "02/subpub/qos2/1322/topic1", 0, proto_ver=proto_ver)
    suback1_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=proto_ver)

    mid = 1
    subscribe2_packet = mqtt_packets.gen_subscribe(mid, "02/subpub/qos2/1322/topic2", 0, proto_ver=proto_ver)
    suback2_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=proto_ver)

    # All publishes have the same mid
    mid = 1
    pubrec_packet = mqtt_packets.gen_pubrec(mid, proto_ver=proto_ver)
    pubrel_packet = mqtt_packets.gen_pubrel(mid, proto_ver=proto_ver)
    pubcomp_packet = mqtt_packets.gen_pubcomp(mid, proto_ver=proto_ver)

    publish1s_packet = mqtt_packets.gen_publish("02/subpub/qos2/1322/topic1", qos=2, mid=mid, payload="message1", proto_ver=proto_ver)
    publish2s_packet = mqtt_packets.gen_publish("02/subpub/qos2/1322/topic2", qos=2, mid=mid, payload="message2", proto_ver=proto_ver)
    publish3s_packet = mqtt_packets.gen_publish("02/subpub/qos2/1322/topic1", qos=2, mid=mid, payload="message3", proto_ver=proto_ver)
    publish4s_packet = mqtt_packets.gen_publish("02/subpub/qos2/1322/topic1", qos=2, mid=mid, payload="message4", proto_ver=proto_ver)
    publish5s_packet = mqtt_packets.gen_publish("02/subpub/qos2/1322/topic1", qos=2, mid=mid, payload="message5", proto_ver=proto_ver)

    publish1r_packet = mqtt_packets.gen_publish("02/subpub/qos2/1322/topic1", qos=0, payload="message1", proto_ver=proto_ver)
    publish2r_packet = mqtt_packets.gen_publish("02/subpub/qos2/1322/topic2", qos=0, payload="message2", proto_ver=proto_ver)
    publish3r_packet = mqtt_packets.gen_publish("02/subpub/qos2/1322/topic1", qos=0, payload="message3", proto_ver=proto_ver)
    publish4r_packet = mqtt_packets.gen_publish("02/subpub/qos2/1322/topic1", qos=0, payload="message4", proto_ver=proto_ver)
    publish5r_packet = mqtt_packets.gen_publish("02/subpub/qos2/1322/topic1", qos=0, payload="message5", proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)

    with broker:
        sub1 = mosq_test.do_client_connect(sub1_connect_packet, sub1_connack_packet, timeout=10, port=port)
        mosq_test.do_send_receive(sub1, subscribe1_packet, suback1_packet, "suback1")

        pub = mosq_test.do_client_connect(pub_connect_packet, pub_connack1_packet, timeout=10, port=port)
        mosq_test.do_send_receive(pub, publish1s_packet, pubrec_packet, "pubrec1")
        mosq_test.do_send_receive(pub, pubrel_packet, pubcomp_packet, "pubcomp1")
        pub.close()

        mosq_test.expect_packet(sub1, "publish1", publish1r_packet)
        pub = mosq_test.do_client_connect(pub_connect_packet, pub_connack2_packet, timeout=10, port=port)
        mosq_test.do_send_receive(pub, publish2s_packet, pubrec_packet, "pubrec2")
        mosq_test.do_send_receive(pub, pubrel_packet, pubcomp_packet, "pubcomp2")
        pub.close()

        # We expect nothing on sub1
        mosq_test.do_ping(sub1, error_string="pingresp1")

        pub = mosq_test.do_client_connect(pub_connect_packet, pub_connack2_packet, timeout=10, port=port)
        mosq_test.do_send_receive(pub, publish3s_packet, pubrec_packet, "pubrec3")
        mosq_test.do_send_receive(pub, pubrel_packet, pubcomp_packet, "pubcomp3")
        pub.close()

        mosq_test.expect_packet(sub1, "publish3", publish3r_packet)
        sub2 = mosq_test.do_client_connect(sub2_connect_packet, sub2_connack_packet, timeout=10, port=port)
        mosq_test.do_send_receive(sub2, subscribe2_packet, suback2_packet, "suback2")

        pub = mosq_test.do_client_connect(pub_connect_packet, pub_connack2_packet, timeout=10, port=port)
        mosq_test.do_send_receive(pub, publish4s_packet, pubrec_packet, "pubrec4")
        mosq_test.do_send_receive(pub, pubrel_packet, pubcomp_packet, "pubcomp4")
        pub.close()

        # We expect nothing on sub2
        mosq_test.do_ping(sub2, error_string="pingresp2")

        mosq_test.expect_packet(sub1, "publish4", publish4r_packet)
        pub = mosq_test.do_client_connect(pub_connect_packet, pub_connack2_packet, timeout=10, port=port)
        mosq_test.do_send_receive(pub, publish5s_packet, pubrec_packet, "pubrec5")
        mosq_test.do_send_receive(pub, pubrel_packet, pubcomp_packet, "pubcomp5")
        pub.close()

        # We expect nothing on sub2
        mosq_test.do_ping(sub2, error_string="pingresp2")

        mosq_test.expect_packet(sub1, "publish5", publish5r_packet)
        sub2.close()
        sub1.close()

        # Clear session
        pub = mosq_test.do_client_connect(pub_connect_packet_clear, pub_connack1_packet, timeout=10, port=port)
        pub.close()


if __name__ == '__main__':
    do_test(proto_ver=4)
    do_test(proto_ver=5)
