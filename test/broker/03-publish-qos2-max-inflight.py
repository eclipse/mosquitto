#!/usr/bin/env python3

# Test whether a PUBLISH to a topic with QoS 2 results in the correct packet flow.
# With max_inflight_messages set to 1

from mosq_test_helper import *
from broker_config import BrokerConfig


def do_test(proto_ver):
    connect_packet = mqtt_packets.gen_connect("pub-qos2-test", proto_ver=proto_ver)
    properties = mqtt5_props.gen_uint16_prop(mqtt5_props.TOPIC_ALIAS_MAXIMUM, 10) \
        + mqtt5_props.gen_uint32_prop(mqtt5_props.MAXIMUM_PACKET_SIZE, 2000000) \
        + mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 1)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver, properties=properties, property_helper=False)

    mid = 312
    publish_packet = mqtt_packets.gen_publish("pub/qos2/test", qos=2, mid=mid, payload="message", proto_ver=proto_ver)
    pubrec_packet = mqtt_packets.gen_pubrec(mid, proto_ver=proto_ver)
    pubrel_packet = mqtt_packets.gen_pubrel(mid, proto_ver=proto_ver)
    pubcomp_packet = mqtt_packets.gen_pubcomp(mid, proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(max_inflight_messages=1)
    broker = MosquittoBroker(port=port, config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port, timeout=10)
        mosq_test.do_send_receive(sock, publish_packet, pubrec_packet, "pubrec")
        mosq_test.do_send_receive(sock, pubrel_packet, pubcomp_packet, "pubcomp")
        sock.close()


do_test(proto_ver=4)
do_test(proto_ver=5)
