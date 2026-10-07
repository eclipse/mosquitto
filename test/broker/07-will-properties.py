#!/usr/bin/env python3

# Test for bug #1244. This occurs if a V5 will message is used where the first
# Will property is one of: content-type, payload-format-indicator,
# response-topic. These are the properties that are attached to the will for
# later use, as opposed to e.g.  will-delay-interval which is a value which is
# read immediately and not passed

from mosq_test_helper import *

def do_test(will_props, recvd_props):
    mid = 1
    connect1_packet = mqtt_packets.gen_connect("07-will-properties-helper", proto_ver=5)
    connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    subscribe1_packet = mqtt_packets.gen_subscribe(mid, "07/will/properties/will/test", 0, proto_ver=5)
    suback1_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=5)

    connect2_packet = mqtt_packets.gen_connect("07-will-properties", proto_ver=5, will_topic="07/will/properties/will/test", will_payload=b"will payload", will_properties=will_props)
    connack2_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    publish_packet = mqtt_packets.gen_publish("07/will/properties/will/test", qos=0, payload="will payload", proto_ver=5, properties=recvd_props)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=30, port=port)
        mosq_test.do_send_receive(sock1, subscribe1_packet, suback1_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=30, port=port)
        sock2.close()

        mosq_test.expect_packet(sock1, "publish", publish_packet)
        sock1.close()


if __name__ == '__main__':
    # Single test property
    will_props = mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "response/topic")
    do_test(will_props, will_props)

    # Multiple test properties
    will_props = mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "response/topic")
    will_props += mqtt5_props.gen_byte_prop(mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 0)
    do_test(will_props, will_props)

    # Multiple test properties, with property that is removed
    will_props = mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "response/topic")
    will_props += mqtt5_props.gen_uint32_prop(mqtt5_props.WILL_DELAY_INTERVAL, 0)
    will_props += mqtt5_props.gen_byte_prop(mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 0)

    recv_props = mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "response/topic")
    recv_props += mqtt5_props.gen_byte_prop(mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 0)
    do_test(will_props, recv_props)

    # Multiple test properties, with property that is removed *first*
    will_props = mqtt5_props.gen_uint32_prop(mqtt5_props.WILL_DELAY_INTERVAL, 0)
    will_props += mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "response/topic")
    will_props += mqtt5_props.gen_string_prop(mqtt5_props.CORRELATION_DATA, "data")

    recv_props = mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "response/topic")
    recv_props += mqtt5_props.gen_string_prop(mqtt5_props.CORRELATION_DATA, "data")
    do_test(will_props, recv_props)

    # All properties,  plus multiple user properties (excluding
    # message-expiry-interval, for ease of testing reasons)
    will_props = mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "key1", "value1")
    will_props += mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "response/topic")
    will_props += mqtt5_props.gen_string_prop(mqtt5_props.CORRELATION_DATA, "data")
    will_props += mqtt5_props.gen_uint32_prop(mqtt5_props.WILL_DELAY_INTERVAL, 0)
    will_props += mqtt5_props.gen_byte_prop(mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 1)
    will_props += mqtt5_props.gen_string_prop(mqtt5_props.CONTENT_TYPE, "application/test")
    will_props += mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "key2", "value2")

    recv_props = mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "key1", "value1")
    recv_props += mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "response/topic")
    recv_props += mqtt5_props.gen_string_prop(mqtt5_props.CORRELATION_DATA, "data")
    recv_props += mqtt5_props.gen_byte_prop(mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 1)
    recv_props += mqtt5_props.gen_string_prop(mqtt5_props.CONTENT_TYPE, "application/test")
    recv_props += mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "key2", "value2")
    do_test(will_props, recv_props)
