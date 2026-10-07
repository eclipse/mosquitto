#!/usr/bin/env python3

# Test whether a PUBLISH to a topic with QoS 1 results in the correct packet flow for a subscriber.
# With max_inflight_messages set to 1

from mosq_test_helper import *
from broker_config import BrokerConfig


def do_test(proto_ver):
    properties = mqtt5_props.gen_uint32_prop(mqtt5_props.SESSION_EXPIRY_INTERVAL, 1000)
    sub_connect_packet = mqtt_packets.gen_connect("sub", properties=properties, proto_ver=proto_ver, clean_session=False)

    properties = mqtt5_props.gen_uint16_prop(mqtt5_props.TOPIC_ALIAS_MAXIMUM, 10) \
        + mqtt5_props.gen_uint32_prop(mqtt5_props.MAXIMUM_PACKET_SIZE, 2000000) \
        + mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 1)
    sub_connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver, properties=properties, property_helper=False)
    sub_connack_packet2 = mqtt_packets.gen_connack(rc=0, flags=1, proto_ver=proto_ver, properties=properties, property_helper=False)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "pub/qos1/test", 1, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 1, proto_ver=proto_ver)

    connect_packet = mqtt_packets.gen_connect("pub-qos1-test", proto_ver=proto_ver)
    properties = mqtt5_props.gen_uint16_prop(mqtt5_props.TOPIC_ALIAS_MAXIMUM, 10) \
        + mqtt5_props.gen_uint32_prop(mqtt5_props.MAXIMUM_PACKET_SIZE, 2000000) \
        + mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 1)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver, properties=properties, property_helper=False)

    mid = 311
    properties = mqtt5_props.gen_uint32_prop(mqtt5_props.MESSAGE_EXPIRY_INTERVAL, 1)
    publish_packet = mqtt_packets.gen_publish("pub/qos1/test", qos=1, mid=mid, payload="message", proto_ver=proto_ver, properties=properties)
    puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)

    mid = 1
    r_publish_packet = mqtt_packets.gen_publish("pub/qos1/test", qos=1, mid=mid, payload="message", proto_ver=proto_ver)
    r_puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(max_inflight_messages=1)
    broker = MosquittoBroker(port=port, config=broker_config)
    with broker:
        sub_sock = mosq_test.do_client_connect(sub_connect_packet, sub_connack_packet, port=port, timeout=10)
        mosq_test.do_send_receive(sub_sock, subscribe_packet, suback_packet, "suback")
        sub_sock.close()

        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port, timeout=10)
        mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")

        time.sleep(2)

        sub_sock = mosq_test.do_client_connect(sub_connect_packet, sub_connack_packet2, port=port, timeout=10)
        # This message has expired, so we don't expect it
        #mosq_test.expect_packet(sub_sock, "publish 2", r_publish_packet)
        #sub_sock.send(r_puback_packet)

        #
        mid = 1
        s_publish_packet = mqtt_packets.gen_publish("pub/qos1/test", qos=1, mid=mid, payload="message2", proto_ver=proto_ver)
        s_puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)
        mosq_test.do_send_receive(sock, s_publish_packet, s_puback_packet, "puback")

        mid = 2
        r_publish_packet = mqtt_packets.gen_publish("pub/qos1/test", qos=1, mid=mid, payload="message2", proto_ver=proto_ver)
        r_puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)
        mosq_test.expect_packet(sub_sock, "publish 3", r_publish_packet)
        sub_sock.send(r_puback_packet)


do_test(proto_ver=5)
