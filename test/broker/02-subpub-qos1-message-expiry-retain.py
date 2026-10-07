#!/usr/bin/env python3

# Test whether the broker reduces the message expiry interval when republishing
# a retained message, and eventually removes it.
# MQTT v5

# Helper publishes a message, with a medium length expiry with retained set. It
# publishes a second message with retained set but no expiry.
# Client connects, subscribes, gets messages, disconnects.
# We wait until the expiry will have expired.
# Client connects, subscribes, doesn't get expired message, does get
# non-expired message.

from mosq_test_helper import *

def do_test(proto_ver):
    keepalive = 60
    connect_packet = mqtt_packets.gen_connect("subpub", keepalive=keepalive, proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 1
    subscribe1_packet = mqtt_packets.gen_subscribe(mid, "subpub/expired", 1, proto_ver=proto_ver)
    suback1_packet = mqtt_packets.gen_suback(mid, 1, proto_ver=proto_ver)

    mid = 2
    subscribe2_packet = mqtt_packets.gen_subscribe(mid, "subpub/kept", 1, proto_ver=proto_ver)
    suback2_packet = mqtt_packets.gen_suback(mid, 1, proto_ver=proto_ver)

    helper_connect = mqtt_packets.gen_connect("helper", proto_ver=proto_ver)
    helper_connack = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    mid=1
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.MESSAGE_EXPIRY_INTERVAL, 2)
    publish1_packet = mqtt_packets.gen_publish("subpub/expired", mid=mid, qos=1, retain=True, payload="message1", proto_ver=proto_ver, properties=props)
    puback1_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver, reason_code=mqtt5_rc.NO_MATCHING_SUBSCRIBERS)

    mid=2
    publish2s_packet = mqtt_packets.gen_publish("subpub/kept", mid=mid, qos=1, retain=True, payload="message2", proto_ver=proto_ver)
    puback2s_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver, reason_code=mqtt5_rc.NO_MATCHING_SUBSCRIBERS)

    mid=1
    publish2r_packet = mqtt_packets.gen_publish("subpub/kept", mid=mid, qos=1, retain=True, payload="message2", proto_ver=proto_ver)
    puback2r_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver, reason_code=mqtt5_rc.NO_MATCHING_SUBSCRIBERS)


    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)

    with broker:
        helper = mosq_test.do_client_connect(helper_connect, helper_connack, timeout=20, port=port)
        mosq_test.do_send_receive(helper, publish1_packet, puback1_packet, "puback 1")
        mosq_test.do_send_receive(helper, publish2s_packet, puback2s_packet, "puback 2")
        helper.close()

        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe1_packet, suback1_packet, "suback 1-1")

        mosq_test.expect_packet(sock, "publish 1", publish1_packet)
        sock.send(puback1_packet)

        mosq_test.do_send_receive(sock, subscribe2_packet, suback2_packet, "suback 2-1")
        mosq_test.expect_packet(sock, "publish 2", publish2s_packet)
        sock.send(puback2s_packet)
        sock.close()

        time.sleep(3)
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe1_packet, suback1_packet, "suback 1-2")
        # We shouldn't receive a publish here
        # This will fail if we do receive a publish
        mosq_test.do_send_receive(sock, subscribe2_packet, suback2_packet, "suback 2-2")
        mosq_test.expect_packet(sock, "publish 2", publish2r_packet)
        sock.send(puback2r_packet)
        sock.close()


do_test(proto_ver=5)
exit(0)
