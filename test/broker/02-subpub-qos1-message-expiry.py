#!/usr/bin/env python3

# Test whether the broker reduces the message expiry interval when republishing.
# MQTT v5

# Client connects with clean session set false, subscribes with qos=1, then disconnects
# Helper publishes two messages, one with a short expiry and one with a long expiry
# We wait until the short expiry will have expired but the long one not.
# Client reconnects, expects delivery of the long expiry message with a reduced
# expiry interval property.

from mosq_test_helper import *

def do_test(proto_ver):
    rc = 1
    mid = 53
    keepalive = 60
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.SESSION_EXPIRY_INTERVAL, 60)
    connect_packet = mqtt_packets.gen_connect("subpub-qos0-test", keepalive=keepalive, proto_ver=proto_ver, clean_session=False, properties=props)
    connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
    connack2_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver, flags=1)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "subpub/qos1", 1, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 1, proto_ver=proto_ver)



    helper_connect = mqtt_packets.gen_connect("helper", proto_ver=proto_ver)
    helper_connack = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    mid=1
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.MESSAGE_EXPIRY_INTERVAL, 1)
    publish1s_packet = mqtt_packets.gen_publish("subpub/qos1", mid=mid, qos=1, payload="message1", proto_ver=proto_ver, properties=props)
    puback1s_packet = mqtt_packets.gen_puback(mid)

    mid=2
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.MESSAGE_EXPIRY_INTERVAL, 10)
    publish2s_packet = mqtt_packets.gen_publish("subpub/qos1", mid=mid, qos=1, payload="message2", proto_ver=proto_ver, properties=props)
    puback2s_packet = mqtt_packets.gen_puback(mid)


    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)

    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack1_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        sock.close()

        helper = mosq_test.do_client_connect(helper_connect, helper_connack, timeout=20, port=port)
        mosq_test.do_send_receive(helper, publish1s_packet, puback1s_packet, "puback 1")
        mosq_test.do_send_receive(helper, publish2s_packet, puback2s_packet, "puback 2")

        time.sleep(2)

        sock = mosq_test.do_client_connect(connect_packet, connack2_packet, timeout=20, port=port)
        packet = sock.recv(len(publish2s_packet))
        for i in range(9, 5, -1):
            props = mqtt5_props.gen_uint32_prop(mqtt5_props.MESSAGE_EXPIRY_INTERVAL, i)
            publish2r_packet = mqtt_packets.gen_publish("subpub/qos1", mid=2, qos=1, payload="message2", proto_ver=proto_ver, properties=props)
            if packet == publish2r_packet:
                rc = 0
                break

        sock.close()
        assert rc == 0


do_test(proto_ver=5)
