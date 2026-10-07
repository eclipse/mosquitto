#!/usr/bin/env python3

# Test whether the broker handles malformed packets correctly - PUBLISH
# MQTTv5

from mosq_test_helper import *
from broker_config import BrokerConfig, ListenerConfig

def do_test(publish_packet, reason_code, error_string):
    connect_packet = mqtt_packets.gen_connect("13-malformed-publish-v5", proto_ver=5)

    connack_props = mqtt5_props.gen_uint16_prop(mqtt5_props.TOPIC_ALIAS_MAXIMUM, 10)
    connack_props += mqtt5_props.gen_byte_prop(mqtt5_props.RETAIN_AVAILABLE, 0)
    connack_props += mqtt5_props.gen_uint32_prop(mqtt5_props.MAXIMUM_PACKET_SIZE, 2000000)
    connack_props += mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 20)
    connack_props += mqtt5_props.gen_byte_prop(mqtt5_props.MAXIMUM_QOS, 1)

    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5, properties=connack_props, property_helper=False)

    mid = 0
    disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5, reason_code=reason_code)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.do_send_receive(sock, publish_packet, disconnect_packet, error_string=error_string)


port = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners=[ListenerConfig(port=port)],
    allow_anonymous=True,
    maximum_qos=1,
    retain_available=False
)
broker = MosquittoBroker(port=port, config=broker_config)
with broker:
    # qos > maximum qos
    publish_packet = mqtt_packets.gen_publish(topic="test/topic", qos=2, mid=1, proto_ver=5)
    do_test(publish_packet, mqtt5_rc.QOS_NOT_SUPPORTED, "qos > maximum qos")

    # retain not supported
    publish_packet = mqtt_packets.gen_publish(topic="test/topic", qos=0, retain=True, proto_ver=5, payload="a")
    do_test(publish_packet, mqtt5_rc.RETAIN_NOT_SUPPORTED, "retain not supported")
